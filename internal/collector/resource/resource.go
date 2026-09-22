// Package resource provides OS-adaptive host resource metric collection.
// All collection is performed via Pure Go APIs (gopsutil / golang.org/x/sys).
package resource

import "time"

// DiskStat holds per-mount-point disk usage and I/O statistics.
type DiskStat struct {
	MountPoint  string  `json:"mount_point"`
	FsType      string  `json:"fs_type"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
	// I/O rates (bytes per second between two consecutive collections)
	ReadBps  float64 `json:"read_bps"`
	WriteBps float64 `json:"write_bps"`
}

// NetStat holds per-interface network traffic statistics.
type NetStat struct {
	Name        string  `json:"name"`
	BytesRecv   uint64  `json:"bytes_recv"`
	BytesSent   uint64  `json:"bytes_sent"`
	PacketsRecv uint64  `json:"packets_recv"`
	PacketsSent uint64  `json:"packets_sent"`
	ErrIn       uint64  `json:"err_in"`
	ErrOut      uint64  `json:"err_out"`
	DropIn      uint64  `json:"drop_in"`
	DropOut     uint64  `json:"drop_out"`
	// Rates calculated between two consecutive collections (Mbps)
	RxMbps float64 `json:"rx_mbps"`
	TxMbps float64 `json:"tx_mbps"`
}

// Metrics is the complete set of host resource metrics for one collection cycle.
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`

	// CPU
	CPUPercent  float64   `json:"cpu_percent"`
	PerCoreCPU  []float64 `json:"per_core_cpu,omitempty"`
	LoadAvg1    float64   `json:"load_avg_1,omitempty"`  // Unix only
	LoadAvg5    float64   `json:"load_avg_5,omitempty"`  // Unix only
	LoadAvg15   float64   `json:"load_avg_15,omitempty"` // Unix only

	// Memory
	MemTotalBytes uint64  `json:"mem_total_bytes"`
	MemUsedBytes  uint64  `json:"mem_used_bytes"`
	MemPercent    float64 `json:"mem_percent"`
	SwapUsedBytes uint64  `json:"swap_used_bytes"`

	// Disk (per mount point)
	Disks []DiskStat `json:"disks"`

	// Network (per interface)
	Interfaces []NetStat `json:"interfaces"`
}

// Collector is the interface implemented by each OS-specific resource collector.
// Collect must be safe to call concurrently.
type Collector interface {
	// Collect gathers the current snapshot.
	// prev is the previous snapshot used to compute rates; may be nil.
	Collect(prev *Metrics) (*Metrics, error)
}
