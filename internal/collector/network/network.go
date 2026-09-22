// Package network provides network interface and ARP/neighbor cache collection.
package network

import (
	"net"
	"time"
)

// ARPEntry represents a single ARP cache / neighbor entry.
type ARPEntry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	Type      string `json:"type,omitempty"` // "dynamic" | "static" | ""
}

// InterfaceInfo holds a network interface's configuration and counters.
type InterfaceInfo struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	MTU         int      `json:"mtu"`
	MAC         string   `json:"mac"`
	Status      string   `json:"status"` // "up" | "down"
	Addrs       []string `json:"addrs"`
	BytesRecv   uint64   `json:"bytes_recv"`
	BytesSent   uint64   `json:"bytes_sent"`
	PacketsRecv uint64   `json:"packets_recv"`
	PacketsSent uint64   `json:"packets_sent"`
	ErrIn       uint64   `json:"err_in"`
	ErrOut      uint64   `json:"err_out"`
	DropIn      uint64   `json:"drop_in"`
	DropOut     uint64   `json:"drop_out"`
}

// Snapshot is a point-in-time view of network state.
type Snapshot struct {
	Timestamp  time.Time       `json:"timestamp"`
	Interfaces []InterfaceInfo `json:"interfaces"`
	ARP        []ARPEntry      `json:"arp"`
}

// GetInterfaces returns the current state of all network interfaces using
// the standard library net package (platform-agnostic).
func GetInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Index: iface.Index,
			Name:  iface.Name,
			MTU:   iface.MTU,
			MAC:   iface.HardwareAddr.String(),
		}

		if iface.Flags&net.FlagUp != 0 {
			info.Status = "up"
		} else {
			info.Status = "down"
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}

		result = append(result, info)
	}
	return result, nil
}

// GetARP is implemented per-OS in arp_{linux,windows,darwin}.go.
// It returns the current ARP / neighbor cache entries.
func GetARP() ([]ARPEntry, error) {
	return getARP()
}

// Collect assembles a complete network Snapshot.
func Collect() (*Snapshot, error) {
	s := &Snapshot{Timestamp: time.Now()}

	ifaces, err := GetInterfaces()
	if err != nil {
		return nil, err
	}
	s.Interfaces = ifaces

	arp, err := GetARP()
	if err == nil {
		s.ARP = arp
	}
	// ARP collection errors are non-fatal.

	return s, nil
}
