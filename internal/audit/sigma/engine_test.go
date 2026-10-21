package sigma

import (
	"runtime"
	"testing"
	"time"
)

func TestSigmaEngineInit(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to initialize sigma engine: %v", err)
	}

	count := eng.RuleCount()
	if count == 0 {
		t.Fatalf("expected loaded rules for %s, got 0", runtime.GOOS)
	}
	t.Logf("loaded %d embedded rules for %s", count, runtime.GOOS)
}

func TestSigmaParseLogData(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to initialize sigma engine: %v", err)
	}

	// 1. JSON parse
	jsonLog := `{"client": "192.168.1.100", "user": "admin", "status": "failed"}`
	parsedJSON := eng.ParseLogData(jsonLog)
	if parsedJSON["client"] != "192.168.1.100" || parsedJSON["user"] != "admin" {
		t.Errorf("unexpected JSON parsed data: %v", parsedJSON)
	}

	// 2. Wazuh sshd decoder test
	wazuhLog := `Failed password for invalid user hacker from 192.168.1.200 port 2222 ssh2`
	parsedWazuh := eng.ParseLogData(wazuhLog)
	if parsedWazuh["user"] != "hacker" || parsedWazuh["client"] != "192.168.1.200" {
		t.Errorf("unexpected Wazuh regex parsed data: %v", parsedWazuh)
	}
}

func TestSigmaRuleMatch(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to initialize sigma engine: %v", err)
	}

	rawLog := "Oct 21 10:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
	matches := eng.MatchAll(rawLog, time.Now().UnixNano())

	if len(matches) == 0 {
		t.Fatalf("expected at least 1 match for sshd failed login, got 0")
	}

	found := false
	for _, m := range matches {
		if m.Evaluator.Rule.ID == "591cb457-3f82-45e7-9d78-b1933f7c4e51" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rule ID 591cb457-3f82-45e7-9d78-b1933f7c4e51 to match, matches: %v", matches)
	}
}

func TestCorrelationTracker(t *testing.T) {
	ct := NewCorrelationTracker()

	config := &CorrelationConfig{
		Frequency: 3,
		Timeframe: 10 * time.Second,
	}

	now := time.Now().UnixNano()

	// 1st hit
	if ct.RecordAndCheck("rule-01", "192.168.1.50", now, config) {
		t.Error("expected false on first hit")
	}

	// 2nd hit
	if ct.RecordAndCheck("rule-01", "192.168.1.50", now+int64(1*time.Second), config) {
		t.Error("expected false on second hit")
	}

	// 3rd hit (threshold reached)
	if !ct.RecordAndCheck("rule-01", "192.168.1.50", now+int64(2*time.Second), config) {
		t.Error("expected true on 3rd hit (threshold reached)")
	}

	// 4th hit (already fired, should not fire again until window resets)
	if ct.RecordAndCheck("rule-01", "192.168.1.50", now+int64(3*time.Second), config) {
		t.Error("expected false on 4th hit (already fired)")
	}
}
