//go:build windows

package resource

import (
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestShouldIncludeWindowsPartition(t *testing.T) {
	tests := []struct {
		name     string
		part     disk.PartitionStat
		expected bool
	}{
		{
			name: "System drive C: NTFS",
			part: disk.PartitionStat{
				Device:     "C:",
				Mountpoint: "C:",
				Fstype:     "NTFS",
				Opts:       []string{"rw"},
			},
			expected: true,
		},
		{
			name: "Data drive D: ReFS",
			part: disk.PartitionStat{
				Device:     "D:",
				Mountpoint: "D:",
				Fstype:     "ReFS",
				Opts:       []string{"rw"},
			},
			expected: true,
		},
		{
			name: "USB drive E: FAT32",
			part: disk.PartitionStat{
				Device:     "E:",
				Mountpoint: "E:",
				Fstype:     "FAT32",
				Opts:       []string{"rw"},
			},
			expected: true,
		},
		{
			name: "CD-ROM / DVD drive CDFS",
			part: disk.PartitionStat{
				Device:     "F:",
				Mountpoint: "F:",
				Fstype:     "CDFS",
				Opts:       []string{"ro"},
			},
			expected: false,
		},
		{
			name: "Virtual ISO UDF",
			part: disk.PartitionStat{
				Device:     "G:",
				Mountpoint: "G:",
				Fstype:     "UDF",
				Opts:       []string{"ro"},
			},
			expected: false,
		},
		{
			name: "Read-only volume",
			part: disk.PartitionStat{
				Device:     "H:",
				Mountpoint: "H:",
				Fstype:     "NTFS",
				Opts:       []string{"ro"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIncludeWindowsPartition(tt.part)
			if got != tt.expected {
				t.Errorf("shouldIncludeWindowsPartition() = %v, want %v", got, tt.expected)
			}
		})
	}
}
