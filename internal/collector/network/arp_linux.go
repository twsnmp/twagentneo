//go:build linux

package network

import (
	"bufio"
	"os"
	"strings"
)

// getARP parses /proc/net/arp to retrieve the ARP cache on Linux.
func getARP() ([]ARPEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []ARPEntry
	scanner := bufio.NewScanner(f)
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Fields: IP HW_TYPE FLAGS MAC MASK IF
		if len(fields) < 6 {
			continue
		}
		// Skip incomplete entries (flags == 0x0)
		if fields[2] == "0x0" {
			continue
		}
		entries = append(entries, ARPEntry{
			IP:        fields[0],
			MAC:       strings.ToLower(fields[3]),
			Interface: fields[5],
			Type:      "dynamic",
		})
	}
	return entries, scanner.Err()
}
