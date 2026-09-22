//go:build windows

package network

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MIB_IPNETROW2 is the Windows struct for a single ARP / neighbor entry.
// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2
type mibIPNetRow2 struct {
	Address        [28]byte // NL_NETWORK_ADDRESS (sockaddr union, max 28 bytes)
	InterfaceIndex uint32
	InterfaceLUID  [8]byte // NET_LUID
	PhysicalAddress        [32]byte
	PhysicalAddressLength  uint32
	State                  uint32 // NL_NEIGHBOR_STATE
	_                      [4]byte // padding / union
	ReachabilityTime       uint64
}

const (
	neighborStatePermanent = 6 // NlnsReachable or permanent
)

var (
	modiphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2   = modiphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable     = modiphlpapi.NewProc("FreeMibTable")
)

// getARP retrieves the ARP / neighbor table via GetIpNetTable2 on Windows.
func getARP() ([]ARPEntry, error) {
	var table uintptr
	// AF_UNSPEC (0) returns both IPv4 and IPv6 neighbours.
	r, _, err := procGetIpNetTable2.Call(uintptr(0), uintptr(unsafe.Pointer(&table)))
	if r != 0 {
		return nil, fmt.Errorf("GetIpNetTable2 failed: %w", err)
	}
	defer procFreeMibTable.Call(table)

	// The returned table starts with a ULONG NumEntries followed by array of rows.
	numEntries := *(*uint32)(unsafe.Pointer(table))
	rowSize := unsafe.Sizeof(mibIPNetRow2{})
	base := table + unsafe.Sizeof(uint32(0))

	var entries []ARPEntry
	for i := uint32(0); i < numEntries; i++ {
		row := (*mibIPNetRow2)(unsafe.Pointer(base + uintptr(i)*rowSize))

		// Parse IP from sockaddr union (first byte is family: 2=IPv4, 23=IPv6)
		family := row.Address[0]
		var ipStr string
		switch family {
		case 2: // AF_INET
			ip := net.IP(row.Address[4:8])
			ipStr = ip.String()
		case 23: // AF_INET6
			ip := net.IP(row.Address[8:24])
			ipStr = ip.String()
		default:
			continue
		}

		if row.PhysicalAddressLength == 0 || row.PhysicalAddressLength > 8 {
			continue
		}
		macBytes := row.PhysicalAddress[:row.PhysicalAddressLength]
		parts := make([]string, len(macBytes))
		for j, b := range macBytes {
			parts[j] = fmt.Sprintf("%02x", b)
		}
		mac := strings.Join(parts, ":")

		entryType := "dynamic"
		if row.State == neighborStatePermanent {
			entryType = "static"
		}

		entries = append(entries, ARPEntry{
			IP:   ipStr,
			MAC:  mac,
			Type: entryType,
		})
	}
	return entries, nil
}
