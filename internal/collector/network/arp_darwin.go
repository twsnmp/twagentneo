//go:build darwin

package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	rtfLLInfo = 0x400 // RTF_LLINFO
	afLink    = 18    // AF_LINK on macOS
)

// getARP retrieves ARP cache entries on macOS via sysctl NET_RT_FLAGS.
func getARP() ([]ARPEntry, error) {
	// sysctl(NET_RT_FLAGS, RTF_LLINFO) returns routing table entries
	// with the RTF_LLINFO flag set, which are ARP/link-layer entries.
	b, err := unix.SysctlRaw("net.route.0.0.flags", rtfLLInfo)
	if err != nil {
		return nil, fmt.Errorf("sysctl NET_RT_FLAGS: %w", err)
	}

	var entries []ARPEntry
	i := 0
	for i < len(b) {
		if i+2 > len(b) {
			break
		}
		msgLen := int(binary.LittleEndian.Uint16(b[i : i+2]))
		if msgLen == 0 || i+msgLen > len(b) {
			break
		}
		msg := b[i : i+msgLen]
		i += msgLen

		// rt_msghdr is the first part; we need at least 92 bytes for the header.
		if len(msg) < 92 {
			continue
		}

		// Addresses start after the 92-byte rt_msghdr.
		addrs := msg[92:]

		// The addrs bitmap (rtm_addrs) is at offset 12 in rt_msghdr.
		rtmAddrs := int32(binary.LittleEndian.Uint32(msg[12:16]))

		// We need RTA_DST (bit 0) and RTA_GATEWAY (bit 1).
		if rtmAddrs&0x3 != 0x3 {
			continue
		}

		// Parse dst (RTA_DST) — first sockaddr.
		ipStr, addrLen := parseSockaddrIP(addrs)
		if ipStr == "" || addrLen == 0 {
			continue
		}

		// Parse gateway (RTA_GATEWAY) — second sockaddr (after dst).
		gateway := addrs[addrLen:]
		if len(gateway) < 2 {
			continue
		}
		if gateway[1] != afLink {
			continue
		}
		mac := parseLinkAddr(gateway)
		if mac == "" {
			continue
		}

		entries = append(entries, ARPEntry{
			IP:   ipStr,
			MAC:  mac,
			Type: "dynamic",
		})
	}
	return entries, nil
}

// parseSockaddrIP extracts an IP string from a sockaddr_in or sockaddr_in6.
// Returns the IP string and the total rounded-up length of the sockaddr.
func parseSockaddrIP(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	saLen := int(b[0])
	saFamily := b[1]
	roundedLen := (saLen + 3) &^ 3 // round up to 4-byte boundary
	if saLen == 0 || roundedLen > len(b) {
		return "", 0
	}
	switch saFamily {
	case syscall.AF_INET:
		if saLen >= 8 {
			return net.IP(b[4:8]).String(), roundedLen
		}
	case syscall.AF_INET6:
		if saLen >= 24 {
			return net.IP(b[8:24]).String(), roundedLen
		}
	}
	return "", roundedLen
}

// parseLinkAddr extracts a MAC address from a sockaddr_dl.
func parseLinkAddr(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	// sockaddr_dl layout: sdl_len(1) sdl_family(1) sdl_index(2) sdl_type(1)
	// sdl_nlen(1) sdl_alen(1) sdl_slen(1) sdl_data(variable)
	nlen := int(b[5]) // interface name length
	alen := int(b[6]) // address (MAC) length
	if alen == 0 || 8+nlen+alen > len(b) {
		return ""
	}
	macBytes := b[8+nlen : 8+nlen+alen]
	parts := make([]string, len(macBytes))
	for i, byt := range macBytes {
		parts[i] = fmt.Sprintf("%02x", byt)
	}
	return strings.Join(parts, ":")
}

// Keep the import alive on darwin builds.
var _ = unsafe.Pointer(nil)
