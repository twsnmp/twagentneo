//go:build darwin

package resource

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// darwinCollector implements Collector for macOS using gopsutil.
type darwinCollector struct{}

// New returns the platform-specific Collector implementation.
func New() Collector {
	return &darwinCollector{}
}

// shouldIncludeDarwinPartition determines whether a disk partition should be monitored on macOS.
// It excludes virtual/pseudo filesystems, internal APFS helper volumes, Time Machine snapshots,
// and filesystems mounted with the "nobrowse" flag.
func shouldIncludeDarwinPartition(p disk.PartitionStat) bool {
	// Skip pseudo-filesystems and network filesystems
	switch p.Fstype {
	case "devfs", "autofs", "nullfs", "smbfs", "nfs", "afpfs":
		return false
	}

	// Skip system internal mounts marked with "nobrowse" (MNT_DONTBROWSE)
	for _, opt := range p.Opts {
		if opt == "nobrowse" {
			return false
		}
	}

	// Skip macOS internal system volume paths (APFS helper volumes)
	if strings.HasPrefix(p.Mountpoint, "/System/Volumes") {
		return false
	}

	// Skip hidden mounts under /Volumes (e.g. /Volumes/.timemachine)
	if strings.HasPrefix(p.Mountpoint, "/Volumes/.") {
		return false
	}

	// Skip Time Machine snapshot pseudo-devices
	if strings.HasPrefix(p.Device, "com.apple.TimeMachine") {
		return false
	}

	return true
}

func (c *darwinCollector) Collect(prev *Metrics) (*Metrics, error) {
	m := &Metrics{Timestamp: time.Now()}

	// --- CPU ---
	cpus, err := cpu.Percent(0, false)
	if err == nil && len(cpus) > 0 {
		m.CPUPercent = cpus[0]
	}
	perCore, err := cpu.Percent(0, true)
	if err == nil {
		m.PerCoreCPU = perCore
	}

	// --- Load average ---
	if la, err := load.Avg(); err == nil {
		m.LoadAvg1 = la.Load1
		m.LoadAvg5 = la.Load5
		m.LoadAvg15 = la.Load15
	}

	// --- Memory ---
	if vm, err := mem.VirtualMemory(); err == nil {
		m.MemTotalBytes = vm.Total
		m.MemUsedBytes = vm.Used
		m.MemPercent = vm.UsedPercent
	}
	if sw, err := mem.SwapMemory(); err == nil {
		m.SwapUsedBytes = sw.Used
	}

	// --- Disk ---
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	parts, err := disk.PartitionsWithContext(ctx, false)
	cancel()
	if err == nil {
		seenDevices := make(map[string]bool)
		for _, p := range parts {
			if !shouldIncludeDarwinPartition(p) {
				continue
			}
			// Deduplicate if multiple mount points use the exact same device
			if p.Device != "" {
				if seenDevices[p.Device] {
					continue
				}
				seenDevices[p.Device] = true
			}

			uctx, ucancel := context.WithTimeout(context.Background(), 2*time.Second)
			usage, err := disk.UsageWithContext(uctx, p.Mountpoint)
			ucancel()
			if err != nil {
				continue
			}
			ds := DiskStat{
				MountPoint:  p.Mountpoint,
				FsType:      p.Fstype,
				TotalBytes:  usage.Total,
				UsedBytes:   usage.Used,
				UsedPercent: usage.UsedPercent,
			}
			m.Disks = append(m.Disks, ds)
		}
	}

	// --- Network ---
	iocounters, err := gopsnet.IOCounters(true)
	if err == nil {
		elapsed := 1.0
		if prev != nil && !prev.Timestamp.IsZero() {
			elapsed = time.Since(prev.Timestamp).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}
		}
		prevMap := make(map[string]NetStat)
		if prev != nil {
			for _, n := range prev.Interfaces {
				prevMap[n.Name] = n
			}
		}
		for _, ioc := range iocounters {
			ns := NetStat{
				Name:        ioc.Name,
				BytesRecv:   ioc.BytesRecv,
				BytesSent:   ioc.BytesSent,
				PacketsRecv: ioc.PacketsRecv,
				PacketsSent: ioc.PacketsSent,
				ErrIn:       ioc.Errin,
				ErrOut:      ioc.Errout,
				DropIn:      ioc.Dropin,
				DropOut:     ioc.Dropout,
			}
			if p, ok := prevMap[ioc.Name]; ok {
				dRecv := float64(ioc.BytesRecv - p.BytesRecv)
				dSent := float64(ioc.BytesSent - p.BytesSent)
				ns.RxMbps = dRecv * 8 / elapsed / 1e6
				ns.TxMbps = dSent * 8 / elapsed / 1e6
			}
			m.Interfaces = append(m.Interfaces, ns)
		}
	}

	return m, nil
}
