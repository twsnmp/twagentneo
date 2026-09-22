// Package aijudge implements Tier-2 local LLM inference for twagentneo.
// It uses internal/ai/tensai to load a GGUF Qwen model and evaluate
// suspicious events flagged by the Sigma engine.
package aijudge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/twsnmp/twagentneo/internal/ai/tensai"
	"github.com/twsnmp/twagentneo/internal/audit"
)

// Judge manages the tensai GGUF LLM engine and evaluates security alerts.
type Judge struct {
	enabled   bool
	timeout   time.Duration
	llm       tensai.LLM
}

// New creates a Judge. If enabled is false, Evaluate() returns nil immediately.
// modelPath must be an absolute path to a GGUF model file (e.g. Qwen2.5-0.5B-Instruct-Q8_0.gguf).
func New(enabled bool, modelPath string, timeout time.Duration) (*Judge, error) {
	j := &Judge{
		enabled: enabled,
		timeout: timeout,
	}
	if !enabled {
		return j, nil
	}
	if modelPath == "" {
		log.Printf("[aijudge] model_path not set — AI judge disabled")
		j.enabled = false
		return j, nil
	}

	llm, err := tensai.New(modelPath)
	if err != nil {
		log.Printf("[aijudge] tensai init failed: %v (AI judge disabled)", err)
		j.enabled = false
		return j, nil
	}

	accType, accDetail := llm.Acceleration()
	log.Printf("[aijudge] tensai ready: accel=%s (%s) timeout=%s", accType, accDetail, timeout)
	j.llm = llm
	return j, nil
}

// Close releases resources held by the tensai engine.
func (j *Judge) Close() {
	if j.llm != nil {
		j.llm.Close()
	}
}

// Evaluate sends the alert to the local LLM for triage.
// Returns nil if the judge is disabled, timed out, or encounters an error —
// the caller should fall back to the Sigma-only alert in that case.
func (j *Judge) Evaluate(alert *audit.SecurityAlert, contextLogs []string) *audit.AIJudgeResult {
	if !j.enabled || j.llm == nil {
		return nil
	}

	prompt := BuildPrompt(alert, contextLogs)
	timeout := j.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := j.llm.GenerateText(ctx, prompt, 512)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[aijudge] timeout evaluating rule %s (timeout=%s)", alert.RuleID, timeout)
		} else {
			log.Printf("[aijudge] inference error rule %s: %v", alert.RuleID, err)
		}
		return nil
	}

	result, err := parseJudgeResponse(resp)
	if err != nil {
		log.Printf("[aijudge] parse error rule %s: %v", alert.RuleID, err)
		return nil
	}
	return result
}

// judgeResponseJSON is the expected JSON structure returned by the LLM.
type judgeResponseJSON struct {
	IsThreat           bool     `json:"is_threat"`
	ComplianceViolated bool     `json:"compliance_violated"`
	ComplianceTypes    []string `json:"compliance_types"`
	Confidence         float64  `json:"confidence"`
	SummaryJa          string   `json:"summary_ja"`
	ActionJa           string   `json:"action_ja"`
}

// parseJudgeResponse extracts the JSON block from the LLM response text.
// LLMs may wrap JSON in markdown code blocks; we search for the raw JSON object.
func parseJudgeResponse(resp string) (*audit.AIJudgeResult, error) {
	start := strings.Index(resp, "{")
	end := strings.LastIndex(resp, "}")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	jsonStr := resp[start : end+1]

	var jr judgeResponseJSON
	if err := json.Unmarshal([]byte(jsonStr), &jr); err != nil {
		return nil, fmt.Errorf("JSON unmarshal: %w", err)
	}

	return &audit.AIJudgeResult{
		IsThreat:           jr.IsThreat,
		ComplianceViolated: jr.ComplianceViolated,
		ComplianceTypes:    jr.ComplianceTypes,
		Confidence:         jr.Confidence,
		SummaryJa:          jr.SummaryJa,
		ActionJa:           jr.ActionJa,
	}, nil
}
