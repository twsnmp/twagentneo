//go:build windows

package resource

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// windowsCollector implements Collector for Windows using gopsutil.
type windowsCollector struct{}

// New returns the platform-specific Collector implementation.
func New() Collector {
	return &windowsCollector{}
}

// shouldIncludeWindowsPartition determines whether a disk partition should be monitored on Windows.
// It excludes optical discs, virtual ISOs, and read-only media to prevent false capacity alerts.
func shouldIncludeWindowsPartition(p disk.PartitionStat) bool {
	// Skip optical drives and virtual ISO images
	switch strings.ToUpper(p.Fstype) {
	case "CDFS", "UDF":
		return false
	}

	// Skip read-only volumes (e.g. CD-ROM, write-protected recovery)
	for _, opt := range p.Opts {
		if opt == "ro" {
			return false
		}
	}

	return true
}

func (c *windowsCollector) Collect(prev *Metrics) (*Metrics, error) {
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
	// LoadAvg is not available on Windows; leave zero values.

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
			if !shouldIncludeWindowsPartition(p) {
				continue
			}
			target := p.Mountpoint
			if target == "" {
				target = p.Device
			}
			if target != "" {
				if seenDevices[target] {
					continue
				}
				seenDevices[target] = true
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
