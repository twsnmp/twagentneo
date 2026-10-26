package exporter

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/config"
)

// OID constants for the twagentNeo MIB.
// Enterprise base: 1.3.6.1.4.1.17862.3 (twagentNeo)
const (
	oidEnterprise    = ".1.3.6.1.4.1.17862"
	oidTwagentNeo    = oidEnterprise + ".3"
	oidObjects       = oidTwagentNeo + ".1"
	oidInfo          = oidObjects + ".1"
	oidTrapObjects   = oidObjects + ".2"
	oidTraps         = oidTwagentNeo + ".2"
	oidTrapsPrefix   = oidTraps + ".0"

	// Info objects
	oidVersion  = oidInfo + ".1.0"
	oidHostname = oidInfo + ".2.0"
	oidOS       = oidInfo + ".3.0"

	// Trap varbind objects
	oidTrapSeverity  = oidTrapObjects + ".1.0"
	oidTrapCategory  = oidTrapObjects + ".2.0"
	oidTrapRuleTitle = oidTrapObjects + ".3.0"
	oidTrapAIJudge   = oidTrapObjects + ".4.0"
	oidTrapAISummary = oidTrapObjects + ".5.0"
	oidTrapAIAction  = oidTrapObjects + ".6.0"

	// Trap OIDs
	oidResourceAlert  = oidTrapsPrefix + ".1"
	oidSecurityAlert  = oidTrapsPrefix + ".2"
	oidFIMAlert       = oidTrapsPrefix + ".3"
	oidHeartbeat      = oidTrapsPrefix + ".4"
)

// AgentVersion is set at build time via ldflags or initialized from main.
var AgentVersion = "v0.3.0"

// SNMPTrapExporter sends SNMP v2c/v3 traps per the twagentNeo MIB (SPEC.md §5).
type SNMPTrapExporter struct {
	cfg      config.SNMPTrapConfig
	gs       *gosnmp.GoSNMP
	hostname string
}

// NewSNMPTrapExporter creates and connects an SNMPTrapExporter.
func NewSNMPTrapExporter(cfg config.SNMPTrapConfig) (*SNMPTrapExporter, error) {
	e := &SNMPTrapExporter{cfg: cfg}
	hostname, _ := os.Hostname()
	e.hostname = hostname

	gs, err := buildGoSNMP(cfg)
	if err != nil {
		return nil, err
	}
	if err := gs.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect: %w", err)
	}
	e.gs = gs
	log.Printf("[snmptrap] connected to %s version=%s", cfg.Target, cfg.Version)
	return e, nil
}

// buildGoSNMP creates a configured GoSNMP instance from config.
func buildGoSNMP(cfg config.SNMPTrapConfig) (*gosnmp.GoSNMP, error) {
	target, port, err := parseTarget(cfg.Target)
	if err != nil {
		return nil, err
	}

	gs := &gosnmp.GoSNMP{
		Target:  target,
		Port:    uint16(port),
		Timeout: 3 * time.Second,
		Retries: 0,
	}

	switch strings.ToLower(cfg.Version) {
	case "v3":
		gs.Version = gosnmp.Version3
		gs.SecurityModel = gosnmp.UserSecurityModel
		gs.SecurityParameters = buildV3Params(cfg.V3)
		gs.MsgFlags = gosnmp.AuthPriv
	default: // v2c
		gs.Version = gosnmp.Version2c
		gs.Community = cfg.Community
	}
	return gs, nil
}

// buildV3Params builds SNMPv3 security parameters.
func buildV3Params(v3 config.SNMPV3Config) *gosnmp.UsmSecurityParameters {
	params := &gosnmp.UsmSecurityParameters{
		UserName: v3.User,
	}

	// Auth protocol
	switch strings.ToUpper(v3.AuthProtocol) {
	case "SHA256":
		params.AuthenticationProtocol = gosnmp.SHA256
	case "SHA224":
		params.AuthenticationProtocol = gosnmp.SHA224
	default:
		params.AuthenticationProtocol = gosnmp.SHA
	}
	params.AuthenticationPassphrase = v3.AuthPassword

	// Privacy protocol
	switch strings.ToUpper(v3.PrivProtocol) {
	case "AES128", "AES":
		params.PrivacyProtocol = gosnmp.AES
	case "AES192":
		params.PrivacyProtocol = gosnmp.AES192
	case "AES256":
		params.PrivacyProtocol = gosnmp.AES256
	default:
		params.PrivacyProtocol = gosnmp.AES
	}
	params.PrivacyPassphrase = v3.PrivPassword

	return params
}

func parseTarget(target string) (string, int, error) {
	port := 162
	parts := strings.SplitN(target, ":", 2)
	host := parts[0]
	if len(parts) == 2 {
		p, err := strconv.Atoi(parts[1])
		if err == nil && p > 0 && p < 65535 {
			port = p
		}
	}
	return host, port, nil
}

// baseVarbinds returns the common varbinds prepended to all traps.
func (e *SNMPTrapExporter) baseVarbinds(trapOID string) []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		{
			Name:  ".1.3.6.1.6.3.1.1.4.1.0", // snmpTrapOID.0
			Type:  gosnmp.ObjectIdentifier,
			Value: trapOID,
		},
		{
			Name:  oidHostname,
			Type:  gosnmp.OctetString,
			Value: e.hostname,
		},
		{
			Name:  oidVersion,
			Type:  gosnmp.OctetString,
			Value: AgentVersion,
		},
		{
			Name:  oidOS,
			Type:  gosnmp.OctetString,
			Value: runtime.GOOS,
		},
	}
}

// SendSecurityAlert sends a twagentNeoSecurityAlert(2) trap.
func (e *SNMPTrapExporter) SendSecurityAlert(alert *audit.SecurityAlert) error {
	vbs := e.baseVarbinds(oidSecurityAlert)
	vbs = append(vbs,
		gosnmp.SnmpPDU{
			Name:  oidTrapSeverity,
			Type:  gosnmp.Integer,
			Value: audit.SeverityInt(alert.Level),
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapCategory,
			Type:  gosnmp.OctetString,
			Value: alert.Category,
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapRuleTitle,
			Type:  gosnmp.OctetString,
			Value: alert.RuleTitle,
		},
	)

	judgeStr := "Threat:NO,CompViolation:NO"
	summaryStr := ""
	actionStr := ""
	if alert.AIJudge != nil {
		threat := "NO"
		if alert.AIJudge.IsThreat {
			threat = "YES"
		}
		comp := "NO"
		if alert.AIJudge.ComplianceViolated {
			comp = "YES"
		}
		judgeStr = fmt.Sprintf("Threat:%s,CompViolation:%s,Conf:%.2f",
			threat, comp, alert.AIJudge.Confidence)
		summaryStr = alert.AIJudge.SummaryJa
		actionStr = alert.AIJudge.ActionJa
	}
	vbs = append(vbs,
		gosnmp.SnmpPDU{Name: oidTrapAIJudge, Type: gosnmp.OctetString, Value: judgeStr},
		gosnmp.SnmpPDU{Name: oidTrapAISummary, Type: gosnmp.OctetString, Value: summaryStr},
		gosnmp.SnmpPDU{Name: oidTrapAIAction, Type: gosnmp.OctetString, Value: actionStr},
	)

	return e.sendTrap(vbs)
}

// SendFIMAlert sends a twagentNeoFIMAlert(3) trap.
func (e *SNMPTrapExporter) SendFIMAlert(ev *audit.FIMEvent) error {
	vbs := e.baseVarbinds(oidFIMAlert)
	vbs = append(vbs,
		gosnmp.SnmpPDU{
			Name:  oidTrapSeverity,
			Type:  gosnmp.Integer,
			Value: 3, // high
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapCategory,
			Type:  gosnmp.OctetString,
			Value: "FIM",
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapRuleTitle,
			Type:  gosnmp.OctetString,
			Value: fmt.Sprintf("File %s: %s", ev.Op, ev.Path),
		},
	)
	return e.sendTrap(vbs)
}

// SendResourceAlert sends a twagentNeoResourceAlert(1) trap.
func (e *SNMPTrapExporter) SendResourceAlert(ra *audit.ResourceAlert) error {
	vbs := e.baseVarbinds(oidResourceAlert)
	vbs = append(vbs,
		gosnmp.SnmpPDU{
			Name:  oidTrapSeverity,
			Type:  gosnmp.Integer,
			Value: 2, // warn
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapCategory,
			Type:  gosnmp.OctetString,
			Value: "Resource",
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapRuleTitle,
			Type:  gosnmp.OctetString,
			Value: fmt.Sprintf("%s threshold exceeded: %.1f%% (threshold: %.1f%%)", ra.Resource, ra.Value, ra.Threshold),
		},
	)
	return e.sendTrap(vbs)
}

// SendHeartbeat sends a twagentNeoHeartbeat(4) trap.
func (e *SNMPTrapExporter) SendHeartbeat() error {
	vbs := e.baseVarbinds(oidHeartbeat)
	vbs = append(vbs,
		gosnmp.SnmpPDU{
			Name:  oidTrapSeverity,
			Type:  gosnmp.Integer,
			Value: 1, // info
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapCategory,
			Type:  gosnmp.OctetString,
			Value: "Heartbeat",
		},
		gosnmp.SnmpPDU{
			Name:  oidTrapRuleTitle,
			Type:  gosnmp.OctetString,
			Value: fmt.Sprintf("Agent %s keepalive", e.hostname),
		},
	)
	return e.sendTrap(vbs)
}

func (e *SNMPTrapExporter) sendTrap(vbs []gosnmp.SnmpPDU) error {
	trap := gosnmp.SnmpTrap{Variables: vbs}
	_, err := e.gs.SendTrap(trap)
	if err != nil {
		log.Printf("[snmptrap] send error: %v", err)
	}
	return err
}

// Close disconnects the SNMP connection.
func (e *SNMPTrapExporter) Close() {
	if e.gs != nil && e.gs.Conn != nil {
		e.gs.Conn.Close()
	}
}
