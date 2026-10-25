//go:build linux

package resource

import (
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestShouldIncludeLinuxPartition(t *testing.T) {
	tests := []struct {
		name     string
		part     disk.PartitionStat
		expected bool
	}{
		{
			name: "Root ext4 partition",
			part: disk.PartitionStat{
				Device:     "/dev/sda1",
				Mountpoint: "/",
				Fstype:     "ext4",
			},
			expected: true,
		},
		{
			name: "Home xfs partition",
			part: disk.PartitionStat{
				Device:     "/dev/nvme0n1p2",
				Mountpoint: "/home",
				Fstype:     "xfs",
			},
			expected: true,
		},
		{
			name: "Loop device / snap",
			part: disk.PartitionStat{
				Device:     "/dev/loop0",
				Mountpoint: "/snap/core20/1822",
				Fstype:     "squashfs",
			},
			expected: false,
		},
		{
			name: "Loop device non-squashfs",
			part: disk.PartitionStat{
				Device:     "/dev/loop1",
				Mountpoint: "/mnt/iso",
				Fstype:     "iso9660",
			},
			expected: false,
		},
		{
			name: "Tmpfs pseudo-fs",
			part: disk.PartitionStat{
				Device:     "tmpfs",
				Mountpoint: "/run",
				Fstype:     "tmpfs",
			},
			expected: false,
		},
		{
			name: "Docker bind mount on ext4",
			part: disk.PartitionStat{
				Device:     "/dev/sda1",
				Mountpoint: "/var/lib/docker/overlay2/abc123def/merged",
				Fstype:     "ext4",
			},
			expected: false,
		},
		{
			name: "Kubelet pod bind mount on ext4",
			part: disk.PartitionStat{
				Device:     "/dev/sda1",
				Mountpoint: "/var/lib/kubelet/pods/uuid/volumes/kubernetes.io~empty-dir/test",
				Fstype:     "ext4",
			},
			expected: false,
		},
		{
			name: "Proc pseudo-fs",
			part: disk.PartitionStat{
				Device:     "proc",
				Mountpoint: "/proc",
				Fstype:     "proc",
			},
			expected: false,
		},
		{
			name: "NFS network mount",
			part: disk.PartitionStat{
				Device:     "192.168.1.10:/exports",
				Mountpoint: "/mnt/nfs",
				Fstype:     "nfs4",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIncludeLinuxPartition(tt.part)
			if got != tt.expected {
				t.Errorf("shouldIncludeLinuxPartition() = %v, want %v", got, tt.expected)
			}
		})
	}
}
