// Package network provides network interface, ARP/neighbor cache, and TCP connection collection.
package network

import (
	"net"
	"strings"
	"sync"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// ARPEntry represents a single ARP cache / neighbor entry.
type ARPEntry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	Type      string `json:"type,omitempty"` // "dynamic" | "static" | ""
}

// InterfaceInfo holds a network interface's configuration, counters, and rates.
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

	// Rates per second calculated between consecutive collections
	RxMbps     float64 `json:"rx_mbps"`
	TxMbps     float64 `json:"tx_mbps"`
	RxPps      float64 `json:"rx_pps"`
	TxPps      float64 `json:"tx_pps"`
	RxErrorPps float64 `json:"rx_error_pps"`
	TxErrorPps float64 `json:"tx_error_pps"`
	RxDropPps  float64 `json:"rx_drop_pps"`
	TxDropPps  float64 `json:"tx_drop_pps"`
}

// InterfaceCollector collects network interface states and tracks traffic rates across collection cycles.
type InterfaceCollector struct {
	mu        sync.Mutex
	prevTime  time.Time
	prevStats map[string]InterfaceInfo
}

// NewInterfaceCollector creates a new InterfaceCollector.
func NewInterfaceCollector() *InterfaceCollector {
	return &InterfaceCollector{
		prevStats: make(map[string]InterfaceInfo),
	}
}

var defaultCollector = NewInterfaceCollector()

// Collect returns the current state of all network interfaces including cumulative counters and unit-time rates.
func (c *InterfaceCollector) Collect() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	iocounters, _ := gopsnet.IOCounters(true)
	iocMap := make(map[string]gopsnet.IOCountersStat, len(iocounters))
	for _, ioc := range iocounters {
		iocMap[ioc.Name] = ioc
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var elapsed float64
	if !c.prevTime.IsZero() {
		elapsed = now.Sub(c.prevTime).Seconds()
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

		// Match IOCounter statistics
		ioc, ok := iocMap[iface.Name]
		if !ok {
			// Fallback: case-insensitive match (for Windows friendly names or varying case)
			for name, stat := range iocMap {
				if strings.EqualFold(name, iface.Name) {
					ioc = stat
					ok = true
					break
				}
			}
		}

		if ok {
			info.BytesRecv = ioc.BytesRecv
			info.BytesSent = ioc.BytesSent
			info.PacketsRecv = ioc.PacketsRecv
			info.PacketsSent = ioc.PacketsSent
			info.ErrIn = ioc.Errin
			info.ErrOut = ioc.Errout
			info.DropIn = ioc.Dropin
			info.DropOut = ioc.Dropout

			if prev, found := c.prevStats[iface.Name]; found && elapsed > 0 {
				if info.BytesRecv >= prev.BytesRecv {
					info.RxMbps = float64(info.BytesRecv-prev.BytesRecv) * 8 / elapsed / 1e6
				}
				if info.BytesSent >= prev.BytesSent {
					info.TxMbps = float64(info.BytesSent-prev.BytesSent) * 8 / elapsed / 1e6
				}
				if info.PacketsRecv >= prev.PacketsRecv {
					info.RxPps = float64(info.PacketsRecv-prev.PacketsRecv) / elapsed
				}
				if info.PacketsSent >= prev.PacketsSent {
					info.TxPps = float64(info.PacketsSent-prev.PacketsSent) / elapsed
				}
				if info.ErrIn >= prev.ErrIn {
					info.RxErrorPps = float64(info.ErrIn-prev.ErrIn) / elapsed
				}
				if info.ErrOut >= prev.ErrOut {
					info.TxErrorPps = float64(info.ErrOut-prev.ErrOut) / elapsed
				}
				if info.DropIn >= prev.DropIn {
					info.RxDropPps = float64(info.DropIn-prev.DropIn) / elapsed
				}
				if info.DropOut >= prev.DropOut {
					info.TxDropPps = float64(info.DropOut-prev.DropOut) / elapsed
				}
			}
		}

		result = append(result, info)
	}

	// Update previous stats cache
	newPrev := make(map[string]InterfaceInfo, len(result))
	for _, info := range result {
		newPrev[info.Name] = info
	}
	c.prevStats = newPrev
	c.prevTime = now

	return result, nil
}

// GetInterfaces returns the current state of all network interfaces using
// the default InterfaceCollector.
func GetInterfaces() ([]InterfaceInfo, error) {
	return defaultCollector.Collect()
}

// GetARP is implemented per-OS in arp_{linux,windows,darwin}.go.
// It returns the current ARP / neighbor cache entries.
func GetARP() ([]ARPEntry, error) {
	return getARP()
}
