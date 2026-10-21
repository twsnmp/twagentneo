package network

import (
	"testing"
)

func TestGetARP(t *testing.T) {
	entries, err := GetARP()
	if err != nil {
		t.Fatalf("GetARP returned error: %v", err)
	}
	t.Logf("GetARP successfully returned %d entries", len(entries))
	for i, e := range entries {
		if i < 5 { // log only first 5 entries
			t.Logf("  Entry[%d]: IP=%s, MAC=%s, Interface=%s, Type=%s", i, e.IP, e.MAC, e.Interface, e.Type)
		}
	}
}

func TestCollectWithARPWatch(t *testing.T) {
	// With ARP collection enabled (default)
	snap1, err := Collect(true)
	if err != nil {
		t.Fatalf("Collect(true) returned error: %v", err)
	}
	t.Logf("Collect(true): %d interfaces, %d ARP entries", len(snap1.Interfaces), len(snap1.ARP))

	// With ARP collection disabled
	snap2, err := Collect(false)
	if err != nil {
		t.Fatalf("Collect(false) returned error: %v", err)
	}
	if len(snap2.ARP) != 0 {
		t.Errorf("expected 0 ARP entries when arp_watch=false, got %d", len(snap2.ARP))
	}
}
