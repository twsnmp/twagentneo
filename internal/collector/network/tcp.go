package network

import (
	"fmt"
	"net"
	"sort"
	"strings"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// TCPConnectionEntry represents an aggregated active TCP destination.
type TCPConnectionEntry struct {
	RemoteIP string   `json:"remote_ip"`
	Process  string   `json:"process,omitempty"`
	Services []string `json:"services"`
	Count    int      `json:"count"`
}

var commonPortServices = map[uint32]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	88:    "kerberos",
	110:   "pop3",
	123:   "ntp",
	139:   "netbios-ssn",
	143:   "imap",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "submission",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	1883:  "mqtt",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	8883:  "mqtts",
	9092:  "kafka",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// resolveService maps a port number to a service name.
func resolveService(port uint32) string {
	if svc, ok := commonPortServices[port]; ok {
		return svc
	}
	return fmt.Sprintf("port/%d", port)
}

// isLoopbackOrLocal checks whether an IP is a loopback or invalid remote address.
func isLoopbackOrLocal(ipStr string) bool {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "::" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

// GetTCPConnections collects and aggregates active TCP connections.
func GetTCPConnections() ([]TCPConnectionEntry, error) {
	conns, err := psnet.Connections("tcp")
	if err != nil {
		return nil, err
	}
	return aggregateTCPConnections(conns), nil
}

// aggregateTCPConnections filters and aggregates raw connection stats.
func aggregateTCPConnections(conns []psnet.ConnectionStat) []TCPConnectionEntry {
	pidCache := make(map[int32]string)
	listenPorts := make(map[uint32]struct{})

	// 1st pass: collect all local listening ports
	for _, c := range conns {
		if strings.EqualFold(c.Status, "LISTEN") && c.Laddr.Port > 0 {
			listenPorts[c.Laddr.Port] = struct{}{}
		}
	}

	type aggKey struct {
		remoteIP string
		process  string
	}

	type aggValue struct {
		count       int
		servicesMap map[string]struct{}
	}

	agg := make(map[aggKey]*aggValue)

	// 2nd pass: process established connections
	for _, c := range conns {
		// Only track established connections
		if !strings.EqualFold(c.Status, "ESTABLISHED") {
			continue
		}

		remoteIP := c.Raddr.IP
		if isLoopbackOrLocal(remoteIP) {
			continue
		}

		// Also ignore if local and remote are identical
		if c.Laddr.IP != "" && c.Laddr.IP == remoteIP {
			continue
		}

		var procName string
		if c.Pid > 0 {
			if name, ok := pidCache[c.Pid]; ok {
				procName = name
			} else {
				if proc, err := process.NewProcess(c.Pid); err == nil {
					if name, err := proc.Name(); err == nil {
						procName = name
					}
				}
				pidCache[c.Pid] = procName
			}
		}

		// Determine target service port:
		// If local port is in listenPorts (or is a known server port while remote is ephemeral),
		// local host is acting as the server (inbound connection).
		var targetPort uint32
		if _, isListen := listenPorts[c.Laddr.Port]; isListen {
			targetPort = c.Laddr.Port
		} else if _, lKnown := commonPortServices[c.Laddr.Port]; lKnown && c.Raddr.Port >= 1024 {
			targetPort = c.Laddr.Port
		} else {
			targetPort = c.Raddr.Port
		}

		service := resolveService(targetPort)
		key := aggKey{
			remoteIP: remoteIP,
			process:  procName,
		}

		entry, exists := agg[key]
		if !exists {
			entry = &aggValue{
				servicesMap: make(map[string]struct{}),
			}
			agg[key] = entry
		}
		entry.count++
		entry.servicesMap[service] = struct{}{}
	}

	result := make([]TCPConnectionEntry, 0, len(agg))
	for k, v := range agg {
		services := make([]string, 0, len(v.servicesMap))
		for s := range v.servicesMap {
			services = append(services, s)
		}
		sort.Strings(services)

		result = append(result, TCPConnectionEntry{
			RemoteIP: k.remoteIP,
			Process:  k.process,
			Services: services,
			Count:    v.count,
		})
	}

	// Sort results for deterministic output
	sort.Slice(result, func(i, j int) bool {
		if result[i].RemoteIP != result[j].RemoteIP {
			return result[i].RemoteIP < result[j].RemoteIP
		}
		return result[i].Process < result[j].Process
	})

	return result
}
