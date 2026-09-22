// Package audit defines data models for the two-tier security auditing engine.
package audit

import "time"

// SecurityAlert is the unified alert structure produced when a Sigma rule matches
// a log event. It is optionally enriched by Tier-2 tensai LLM inference.
type SecurityAlert struct {
	Timestamp   time.Time              `json:"timestamp"`
	RuleID      string                 `json:"rule_id"`
	RuleTitle   string                 `json:"rule_title"`
	Level       string                 `json:"level"`    // low | medium | high | critical
	Category    string                 `json:"category"` // e.g. "Authentication", "Privilege Escalation"
	SourceLog   string                 `json:"source_log"`
	MatchedData map[string]interface{} `json:"matched_data"`

	// AIJudge is populated by Tier-2 (tensai) evaluation.
	// nil when tensai is disabled, timed out, or encountered an error (fallback mode).
	AIJudge *AIJudgeResult `json:"ai_judge,omitempty"`
}

// AIJudgeResult holds the output of a tensai LLM inference run against
// a suspicious event flagged by Tier-1 Sigma evaluation.
type AIJudgeResult struct {
	// IsThreat indicates whether the event represents an actual security threat
	// (true) or is likely a false positive such as admin maintenance (false).
	IsThreat bool `json:"is_threat"`

	// ComplianceViolated indicates a policy/compliance breach was detected.
	ComplianceViolated bool `json:"compliance_violated"`

	// ComplianceTypes lists violated compliance categories, e.g.:
	// "Privilege_Abuse", "Unauthorized_Access", "Data_Exfiltration".
	ComplianceTypes []string `json:"compliance_types"`

	// Confidence is the model's self-reported certainty score [0.0, 1.0].
	Confidence float64 `json:"confidence"`

	// SummaryJa is a human-readable Japanese summary of the event context.
	SummaryJa string `json:"summary_ja"`

	// ActionJa is the recommended immediate countermeasure in Japanese.
	ActionJa string `json:"action_ja"`
}

// SeverityInt converts a string level into an integer for SNMP varbind encoding.
// Matches the MIB: info(1), warn(2), high(3), critical(4).
func SeverityInt(level string) int {
	switch level {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "warn":
		return 2
	default:
		return 1
	}
}

// FIMEvent is produced by the File Integrity Monitoring collector.
type FIMEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Op        string    `json:"op"`   // "create" | "write" | "remove" | "chmod" | "rename"
	Path      string    `json:"path"` // affected file path
	Hash      string    `json:"hash,omitempty"` // SHA-256 hex digest (empty for remove)
}

// ResourceAlert is produced when a host resource threshold is exceeded.
type ResourceAlert struct {
	Timestamp time.Time `json:"timestamp"`
	Resource  string    `json:"resource"`  // "cpu" | "mem" | "disk" | "load"
	MountPath string    `json:"mount_path,omitempty"` // disk mount point
	Threshold float64   `json:"threshold"` // configured threshold %
	Value     float64   `json:"value"`     // current measured value %
}
