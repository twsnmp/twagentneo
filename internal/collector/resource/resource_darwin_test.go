//go:build darwin

package resource

import (
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestCollectorLive(t *testing.T) {
	col := New()
	m, err := col.Collect(nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	t.Logf("Collected %d disks on host:", len(m.Disks))
	for _, d := range m.Disks {
		t.Logf("- Mount: %-25s Fstype: %-6s Used: %6.2f%% Total: %d bytes",
			d.MountPoint, d.FsType, d.UsedPercent, d.TotalBytes)
	}
	if len(m.Disks) == 0 {
		t.Errorf("expected at least 1 disk (root /)")
	}
	// Verify that /System/Volumes is NOT in any collected disk
	for _, d := range m.Disks {
		if d.MountPoint == "/System/Volumes/Data" || d.MountPoint == "/System/Volumes/VM" {
			t.Errorf("found unwanted internal mount: %s", d.MountPoint)
		}
	}
}

func TestShouldIncludeDarwinPartition(t *testing.T) {
	tests := []struct {
		name     string
		part     disk.PartitionStat
		expected bool
	}{
		{
			name: "Root partition APFS",
			part: disk.PartitionStat{
				Device:     "/dev/disk3s1s1",
				Mountpoint: "/",
				Fstype:     "apfs",
				Opts:       []string{"ro", "journaled", "multilabel"},
			},
			expected: true,
		},
		{
			name: "External disk APFS",
			part: disk.PartitionStat{
				Device:     "/dev/disk7s1",
				Mountpoint: "/Volumes/SUBDISK1TB",
				Fstype:     "apfs",
				Opts:       []string{"rw", "nosuid", "journaled", "multilabel", "nodev"},
			},
			expected: true,
		},
		{
			name: "External disk ExFAT",
			part: disk.PartitionStat{
				Device:     "/dev/disk8s1",
				Mountpoint: "/Volumes/UsbDrive",
				Fstype:     "exfat",
				Opts:       []string{"rw", "nosuid", "nodev"},
			},
			expected: true,
		},
		{
			name: "nobrowse APFS internal VM",
			part: disk.PartitionStat{
				Device:     "/dev/disk3s6",
				Mountpoint: "/System/Volumes/VM",
				Fstype:     "apfs",
				Opts:       []string{"rw", "noexec", "nobrowse", "journaled", "multilabel", "noatime"},
			},
			expected: false,
		},
		{
			name: "nobrowse APFS internal Data",
			part: disk.PartitionStat{
				Device:     "/dev/disk3s5",
				Mountpoint: "/System/Volumes/Data",
				Fstype:     "apfs",
				Opts:       []string{"rw", "nobrowse", "journaled", "multilabel"},
			},
			expected: false,
		},
		{
			name: "nobrowse APFS internal Preboot",
			part: disk.PartitionStat{
				Device:     "/dev/disk3s2",
				Mountpoint: "/System/Volumes/Preboot",
				Fstype:     "apfs",
				Opts:       []string{"rw", "nobrowse", "journaled", "multilabel"},
			},
			expected: false,
		},
		{
			name: "nobrowse APFS internal Update/mnt1",
			part: disk.PartitionStat{
				Device:     "/dev/disk3s1",
				Mountpoint: "/System/Volumes/Update/mnt1",
				Fstype:     "apfs",
				Opts:       []string{"rw", "nobrowse", "journaled", "multilabel"},
			},
			expected: false,
		},
		{
			name: "TimeMachine snapshot mount",
			part: disk.PartitionStat{
				Device:     "com.apple.TimeMachine.2025-03-10-170819.backup@/dev/disk9s2",
				Mountpoint: "/Volumes/.timemachine/629832D4-D518-47A1-89F8-B6639E884987/2025-03-10-170819.backup",
				Fstype:     "apfs",
				Opts:       []string{"ro", "nosuid", "nobrowse", "journaled", "multilabel", "nodev"},
			},
			expected: false,
		},
		{
			name: "devfs pseudo-fs",
			part: disk.PartitionStat{
				Device:     "devfs",
				Mountpoint: "/dev",
				Fstype:     "devfs",
				Opts:       []string{"nobrowse"},
			},
			expected: false,
		},
		{
			name: "autofs pseudo-fs",
			part: disk.PartitionStat{
				Device:     "map auto_home",
				Mountpoint: "/System/Volumes/Data/home",
				Fstype:     "autofs",
				Opts:       []string{"nobrowse"},
			},
			expected: false,
		},
		{
			name: "smbfs network share",
			part: disk.PartitionStat{
				Device:     "//user@server/share",
				Mountpoint: "/Volumes/share",
				Fstype:     "smbfs",
				Opts:       []string{"nodev", "nosuid"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIncludeDarwinPartition(tt.part)
			if got != tt.expected {
				t.Errorf("shouldIncludeDarwinPartition() = %v, want %v", got, tt.expected)
			}
		})
	}
}
