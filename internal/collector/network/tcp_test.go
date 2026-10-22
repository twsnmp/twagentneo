package network

import (
	"testing"

	psnet "github.com/shirou/gopsutil/v4/net"
)

func TestResolveService(t *testing.T) {
	tests := []struct {
		port     uint32
		expected string
	}{
		{443, "https"},
		{80, "http"},
		{22, "ssh"},
		{1883, "mqtt"},
		{8883, "mqtts"},
		{12345, "port/12345"},
	}

	for _, tt := range tests {
		got := resolveService(tt.port)
		if got != tt.expected {
			t.Errorf("resolveService(%d) = %q, want %q", tt.port, got, tt.expected)
		}
	}
}

func TestIsLoopbackOrLocal(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"", true},
		{"invalid-ip", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		got := isLoopbackOrLocal(tt.ip)
		if got != tt.expected {
			t.Errorf("isLoopbackOrLocal(%q) = %v, want %v", tt.ip, got, tt.expected)
		}
	}
}

func TestAggregateTCPConnections(t *testing.T) {
	conns := []psnet.ConnectionStat{
		{
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 50000},
			Raddr:  psnet.Addr{IP: "142.250.196.110", Port: 443},
			Pid:    101,
		},
		{
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 50001},
			Raddr:  psnet.Addr{IP: "142.250.196.110", Port: 80},
			Pid:    101,
		},
		{
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 50002},
			Raddr:  psnet.Addr{IP: "142.250.196.110", Port: 443},
			Pid:    101,
		},
		{
			// Loopback connection (should be ignored)
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "127.0.0.1", Port: 8080},
			Raddr:  psnet.Addr{IP: "127.0.0.1", Port: 50003},
			Pid:    102,
		},
		{
			// Listen socket (should be ignored)
			Status: "LISTEN",
			Laddr:  psnet.Addr{IP: "0.0.0.0", Port: 8080},
			Raddr:  psnet.Addr{IP: "", Port: 0},
			Pid:    103,
		},
		{
			// Another remote host (outbound)
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 50004},
			Raddr:  psnet.Addr{IP: "192.168.1.50", Port: 22},
			Pid:    104,
		},
		{
			// Inbound connection: local host is server listening on 443
			Status: "LISTEN",
			Laddr:  psnet.Addr{IP: "0.0.0.0", Port: 443},
			Raddr:  psnet.Addr{IP: "", Port: 0},
			Pid:    105,
		},
		{
			// Inbound connection from client 10.0.0.1 to local 443
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 443},
			Raddr:  psnet.Addr{IP: "10.0.0.1", Port: 54321},
			Pid:    105,
		},
		{
			// Another inbound connection from client 10.0.0.1 to local 443
			Status: "ESTABLISHED",
			Laddr:  psnet.Addr{IP: "192.168.1.100", Port: 443},
			Raddr:  psnet.Addr{IP: "10.0.0.1", Port: 54322},
			Pid:    105,
		},
	}

	result := aggregateTCPConnections(conns)

	if len(result) != 3 {
		t.Fatalf("expected 3 aggregated entries, got %d", len(result))
	}

	// First should be 10.0.0.1 (inbound server connection)
	e0 := result[0]
	if e0.RemoteIP != "10.0.0.1" {
		t.Errorf("entry 0: RemoteIP = %q, want 10.0.0.1", e0.RemoteIP)
	}
	if e0.Count != 2 {
		t.Errorf("entry 0: Count = %d, want 2", e0.Count)
	}
	if len(e0.Services) != 1 || e0.Services[0] != "https" {
		t.Errorf("entry 0: Services = %v, want [https]", e0.Services)
	}

	// Second should be 142.250.196.110
	e1 := result[1]
	if e1.RemoteIP != "142.250.196.110" {
		t.Errorf("entry 1: RemoteIP = %q, want 142.250.196.110", e1.RemoteIP)
	}
	if e1.Count != 3 {
		t.Errorf("entry 1: Count = %d, want 3", e1.Count)
	}
	if len(e1.Services) != 2 || e1.Services[0] != "http" || e1.Services[1] != "https" {
		t.Errorf("entry 1: Services = %v, want [http https]", e1.Services)
	}

	// Third should be 192.168.1.50
	e2 := result[2]
	if e2.RemoteIP != "192.168.1.50" {
		t.Errorf("entry 1: RemoteIP = %q, want 192.168.1.50", e2.RemoteIP)
	}
	if e2.Count != 1 {
		t.Errorf("entry 1: Count = %d, want 1", e2.Count)
	}
	if len(e2.Services) != 1 || e2.Services[0] != "ssh" {
		t.Errorf("entry 1: Services = %v, want [ssh]", e2.Services)
	}
}

func TestGetTCPConnections(t *testing.T) {
	// Smoke test: should run without runtime errors
	_, err := GetTCPConnections()
	if err != nil {
		t.Logf("GetTCPConnections error (may require OS privileges): %v", err)
	}
}
