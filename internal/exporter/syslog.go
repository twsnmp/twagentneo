package exporter

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/config"
)

// SyslogExporter sends RFC 5424 syslog messages over UDP, TCP, or TLS.
type SyslogExporter struct {
	cfg      config.SyslogConfig
	hostname string
	conn     net.Conn
}

// NewSyslogExporter creates and connects a SyslogExporter.
// Endpoint format: "udp://host:port", "tcp://host:port", or "tls://host:port".
func NewSyslogExporter(cfg config.SyslogConfig) (*SyslogExporter, error) {
	e := &SyslogExporter{cfg: cfg}
	hostname, _ := os.Hostname()
	e.hostname = hostname

	proto, addr, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("syslog: parse endpoint: %w", err)
	}

	conn, err := net.Dial(proto, addr)
	if err != nil {
		return nil, fmt.Errorf("syslog: connect %s: %w", cfg.Endpoint, err)
	}
	e.conn = conn
	log.Printf("[syslog] connected to %s", cfg.Endpoint)
	return e, nil
}

// parseEndpoint splits an endpoint URL into network and address.
func parseEndpoint(endpoint string) (proto, addr string, err error) {
	switch {
	case strings.HasPrefix(endpoint, "udp://"):
		return "udp", strings.TrimPrefix(endpoint, "udp://"), nil
	case strings.HasPrefix(endpoint, "tcp://"):
		return "tcp", strings.TrimPrefix(endpoint, "tcp://"), nil
	case strings.HasPrefix(endpoint, "tls://"):
		return "tcp", strings.TrimPrefix(endpoint, "tls://"), nil
	default:
		return "udp", endpoint, nil
	}
}

// SendAlert sends a security alert as an RFC 5424 syslog message.
func (e *SyslogExporter) SendAlert(alert *audit.SecurityAlert) error {
	severity := syslogSeverity(alert.Level)

	// RFC 5424 Structured Data
	judgeStr := "NO"
	compStr := "NO"
	if alert.AIJudge != nil {
		if alert.AIJudge.IsThreat {
			judgeStr = "YES"
		}
		if alert.AIJudge.ComplianceViolated {
			compStr = "YES"
		}
	}
	sd := fmt.Sprintf(`[twsnmpneo@17862 rule="%s" threat="%s" comp="%s"]`,
		escapeSDValue(alert.RuleTitle), judgeStr, compStr)

	msg := e.rfc5424(severity, "twagentneo", sd,
		fmt.Sprintf("%s: %s", alert.Category, alert.SourceLog))
	return e.send(msg)
}

// SendFIM sends a FIM event as a syslog message.
func (e *SyslogExporter) SendFIM(ev *audit.FIMEvent) error {
	sd := fmt.Sprintf(`[twsnmpneo@17862 op="%s" path="%s"]`,
		ev.Op, escapeSDValue(ev.Path))
	msg := e.rfc5424(syslogSeverity("high"), "twagentneo-fim", sd,
		fmt.Sprintf("FIM %s: %s", ev.Op, ev.Path))
	return e.send(msg)
}

// SendResourceAlert sends a resource alert as a syslog message.
func (e *SyslogExporter) SendResourceAlert(ra *audit.ResourceAlert) error {
	sd := fmt.Sprintf(`[twsnmpneo@17862 resource="%s" val="%.1f" thresh="%.1f"]`,
		ra.Resource, ra.Value, ra.Threshold)
	msg := e.rfc5424(syslogSeverity("warn"), "twagentneo-resource", sd,
		fmt.Sprintf("Resource %s exceeded threshold: %.1f%% (threshold: %.1f%%)",
			ra.Resource, ra.Value, ra.Threshold))
	return e.send(msg)
}

// rfc5424 formats a message according to RFC 5424.
// facility=1 (user), priority = facility*8 + severity.
func (e *SyslogExporter) rfc5424(severity int, appName, structuredData, msg string) string {
	pri := 1*8 + severity
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	return fmt.Sprintf("<%d>1 %s %s %s - - %s %s",
		pri, ts, e.hostname, appName, structuredData, msg)
}

func (e *SyslogExporter) send(msg string) error {
	if e.conn == nil {
		return fmt.Errorf("syslog: not connected")
	}
	_, err := fmt.Fprintln(e.conn, msg)
	return err
}

// Close shuts down the syslog connection.
func (e *SyslogExporter) Close() {
	if e.conn != nil {
		e.conn.Close()
	}
}

// syslogSeverity maps an alert level to RFC 5424 severity.
// 2=critical, 3=error, 4=warning, 5=notice, 6=info
func syslogSeverity(level string) int {
	switch level {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium", "warn":
		return 4
	case "low":
		return 5
	default:
		return 6
	}
}

// escapeSDValue escapes special characters in RFC 5424 Structured Data values.
func escapeSDValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}
