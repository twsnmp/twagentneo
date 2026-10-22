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

func TestGetInterfaces(t *testing.T) {
	ifaces, err := GetInterfaces()
	if err != nil {
		t.Fatalf("GetInterfaces returned error: %v", err)
	}
	t.Logf("GetInterfaces returned %d interfaces", len(ifaces))
	if len(ifaces) == 0 {
		t.Errorf("expected at least 1 interface")
	}
}
