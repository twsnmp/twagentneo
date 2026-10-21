package aijudge

import (
	"strings"
	"testing"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
)

func TestBuildPrompt(t *testing.T) {
	alert := &audit.SecurityAlert{
		Timestamp: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		RuleID:    "test-rule-001",
		RuleTitle: "Test SSH Brute Force",
		Level:     "high",
		Category:  "Authentication",
		SourceLog: "/var/log/auth.log",
		MatchedData: map[string]interface{}{
			"user":   "root",
			"client": "192.168.1.100",
		},
	}

	contextLogs := []string{
		"Oct 21 09:59:58 connection from 192.168.1.100",
		"Oct 21 09:59:59 failed password for root",
	}

	prompt := BuildPrompt(alert, contextLogs)

	if !strings.Contains(prompt, "test-rule-001") {
		t.Error("prompt should contain RuleID")
	}
	if !strings.Contains(prompt, "Test SSH Brute Force") {
		t.Error("prompt should contain RuleTitle")
	}
	if !strings.Contains(prompt, "192.168.1.100") {
		t.Error("prompt should contain matched client IP")
	}
	if !strings.Contains(prompt, "Oct 21 09:59:58") {
		t.Error("prompt should contain context logs")
	}
}

func TestParseJudgeResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantThreat bool
		wantComp   bool
		wantErr    bool
	}{
		{
			name: "pure json",
			input: `{
				"is_threat": true,
				"compliance_violated": true,
				"compliance_types": ["Privilege_Abuse"],
				"confidence": 0.95,
				"summary_ja": "ルートアカウントへの辞書攻撃が検知されました。",
				"action_ja": "IPアドレス 192.168.1.100 をファイアウォールでブロックしてください。"
			}`,
			wantThreat: true,
			wantComp:   true,
			wantErr:    false,
		},
		{
			name: "wrapped in markdown code block",
			input: "分析結果は以下の通りです。\n```json\n" +
				`{"is_threat": false, "compliance_violated": false, "confidence": 0.1, "summary_ja": "正常な管理者ログインです。", "action_ja": "対応不要です。"}` +
				"\n```\n以上です。",
			wantThreat: false,
			wantComp:   false,
			wantErr:    false,
		},
		{
			name:       "invalid non-json response",
			input:      "すみません、JSON形式で出力できませんでした。",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseJudgeResponse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.IsThreat != tt.wantThreat {
				t.Errorf("got IsThreat=%v, want %v", res.IsThreat, tt.wantThreat)
			}
			if res.ComplianceViolated != tt.wantComp {
				t.Errorf("got ComplianceViolated=%v, want %v", res.ComplianceViolated, tt.wantComp)
			}
		})
	}
}

func TestJudgeDisabled(t *testing.T) {
	j, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer j.Close()

	res := j.Evaluate(&audit.SecurityAlert{}, nil)
	if res != nil {
		t.Errorf("expected nil for disabled judge, got %v", res)
	}
}
