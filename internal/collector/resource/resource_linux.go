//go:build linux

package resource

import (
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// linuxCollector implements Collector for Linux using gopsutil.
type linuxCollector struct{}

// New returns the platform-specific Collector implementation.
func New() Collector {
	return &linuxCollector{}
}

func (c *linuxCollector) Collect(prev *Metrics) (*Metrics, error) {
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
	parts, err := disk.Partitions(false)
	if err == nil {
		for _, p := range parts {
			usage, err := disk.Usage(p.Mountpoint)
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
