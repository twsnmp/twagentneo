package network

import (
	"testing"
	"time"
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
	collector := NewInterfaceCollector()
	ifaces1, err := collector.Collect()
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	t.Logf("Collect returned %d interfaces", len(ifaces1))
	if len(ifaces1) == 0 {
		t.Errorf("expected at least 1 interface")
	}

	var hasTraffic bool
	for _, iface := range ifaces1 {
		if iface.BytesRecv > 0 || iface.BytesSent > 0 {
			hasTraffic = true
			t.Logf("  Interface %s: status=%s, rx_bytes=%d, tx_bytes=%d, rx_mbps=%.4f",
				iface.Name, iface.Status, iface.BytesRecv, iface.BytesSent, iface.RxMbps)
		}
	}
	if !hasTraffic {
		t.Logf("Warning: no traffic counters found on any interface (may happen in some test containers)")
	}

	// Wait briefly and collect again to test rate calculation
	time.Sleep(100 * time.Millisecond)
	ifaces2, err := collector.Collect()
	if err != nil {
		t.Fatalf("Second Collect returned error: %v", err)
	}
	for _, iface := range ifaces2 {
		if iface.BytesRecv > 0 || iface.BytesSent > 0 {
			t.Logf("  Second pass Interface %s: rx_mbps=%.4f, tx_mbps=%.4f, rx_pps=%.2f, tx_pps=%.2f",
				iface.Name, iface.RxMbps, iface.TxMbps, iface.RxPps, iface.TxPps)
		}
	}
}
