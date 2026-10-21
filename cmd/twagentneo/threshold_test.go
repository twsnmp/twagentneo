package main

import (
	"testing"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/collector/resource"
	"github.com/twsnmp/twagentneo/internal/config"
	"github.com/twsnmp/twagentneo/internal/pipeline"
)

func TestCheckResourceThresholds(t *testing.T) {
	bus := pipeline.New()
	defer bus.Stop()

	sub := bus.Subscribe()
	defer sub.Close()

	cfg := config.ResourceCollectorConfig{
		CPUThreshold:  80.0,
		MemThreshold:  85.0,
		DiskThreshold: 90.0,
		LoadThreshold: 5.0,
	}

	m := &resource.Metrics{
		Timestamp:  time.Now(),
		CPUPercent: 95.0, // exceeds 80.0
		MemPercent: 70.0, // below 85.0
		Disks: []resource.DiskStat{
			{MountPoint: "/", UsedPercent: 92.5},   // exceeds 90.0
			{MountPoint: "/data", UsedPercent: 50.0}, // below 90.0
		},
		LoadAvg1: 1.2, // below 5.0
	}

	checkResourceThresholds(m, cfg, bus)

	var alerts []*audit.ResourceAlert
	timeout := time.After(500 * time.Millisecond)

collect:
	for {
		select {
		case ev := <-sub.C:
			if ev.Type == pipeline.EventTypeResourceAlert {
				ra, ok := ev.Payload.(*audit.ResourceAlert)
				if ok {
					alerts = append(alerts, ra)
				}
			}
		case <-timeout:
			break collect
		}
	}

	// Should trigger 2 alerts: CPU and Disk /
	if len(alerts) != 2 {
		t.Fatalf("expected 2 resource alerts, got %d", len(alerts))
	}

	cpuFound := false
	diskFound := false
	for _, a := range alerts {
		if a.Resource == "cpu" && a.Value == 95.0 {
			cpuFound = true
		}
		if a.Resource == "disk" && a.MountPath == "/" && a.Value == 92.5 {
			diskFound = true
		}
	}

	if !cpuFound {
		t.Error("expected CPU threshold alert")
	}
	if !diskFound {
		t.Error("expected Disk / threshold alert")
	}
}
