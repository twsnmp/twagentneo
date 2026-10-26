package sca

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/config"
	"github.com/twsnmp/twagentneo/internal/pipeline"
)

func TestAuditor_ScanDirectoryAndFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sca_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Secrets file (.env)
	envContent := `
PORT=8080
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
SLACK_URL=https://hooks.slack.com/services/T1234/B5678/abcdefg12345
DB_PASSWORD="super-secret-password-1234"
`
	envPath := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// 2. Backup file
	bakPath := filepath.Join(tempDir, "database.sql.bak")
	if err := os.WriteFile(bakPath, []byte("SELECT * FROM users;"), 0644); err != nil {
		t.Fatalf("failed to write bak: %v", err)
	}

	// 3. sshd_config
	sshContent := `
Protocol 1
PermitRootLogin yes
PasswordAuthentication yes
`
	sshPath := filepath.Join(tempDir, "sshd_config")
	if err := os.WriteFile(sshPath, []byte(sshContent), 0644); err != nil {
		t.Fatalf("failed to write sshd_config: %v", err)
	}

	// 4. sysctl.conf
	sysctlContent := `
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
`
	sysctlPath := filepath.Join(tempDir, "sysctl.conf")
	if err := os.WriteFile(sysctlPath, []byte(sysctlContent), 0644); err != nil {
		t.Fatalf("failed to write sysctl.conf: %v", err)
	}

	// 5. Unix file permissions
	if runtime.GOOS != "windows" {
		keyPath := filepath.Join(tempDir, "id_rsa")
		keyContent := "-----BEGIN RSA PRIVATE KEY-----\nMOCKKEYDATA\n-----END RSA PRIVATE KEY-----"
		// Loose permission (group & others readable)
		if err := os.WriteFile(keyPath, []byte(keyContent), 0644); err != nil {
			t.Fatalf("failed to write id_rsa: %v", err)
		}

		// World writable file
		wwPath := filepath.Join(tempDir, "world_writable.txt")
		if err := os.WriteFile(wwPath, []byte("hello"), 0666); err != nil {
			t.Fatalf("failed to write world_writable: %v", err)
		}
	}

	auditor := NewAuditor(100, 1024*1024)

	// Test ScanFile on single file
	sshFindings, err := auditor.ScanFile(sshPath)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(sshFindings) < 3 {
		t.Errorf("expected at least 3 findings for sshd_config, got %d", len(sshFindings))
	}

	// Test ScanDirectory
	findings, err := auditor.ScanDirectory(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	ruleCounts := make(map[string]int)
	for _, f := range findings {
		ruleCounts[f.RuleID]++
		// Verify conversion to SecurityAlert
		alert := f.ToSecurityAlert()
		if alert.RuleID != f.RuleID || alert.Level != f.Severity {
			t.Errorf("ToSecurityAlert mismatch: %+v != %+v", alert, f)
		}
	}

	if ruleCounts["CIS-3.12"] < 3 {
		t.Errorf("expected >= 3 CIS-3.12 (secrets) findings, got %d", ruleCounts["CIS-3.12"])
	}
	if ruleCounts["CIS-4.7"] < 1 {
		t.Errorf("expected >= 1 CIS-4.7 (backup) finding, got %d", ruleCounts["CIS-4.7"])
	}
	if ruleCounts["CIS-4.1"] < 3 {
		t.Errorf("expected >= 3 CIS-4.1 (ssh root/proto, sysctl), got %d", ruleCounts["CIS-4.1"])
	}
	if ruleCounts["CIS-4.8"] < 1 {
		t.Errorf("expected >= 1 CIS-4.8 (ssh password auth), got %d", ruleCounts["CIS-4.8"])
	}

	if runtime.GOOS != "windows" {
		if ruleCounts["CIS-3.14"] < 2 {
			t.Errorf("expected >= 2 CIS-3.14 (permissions) findings on Unix, got %d", ruleCounts["CIS-3.14"])
		}
	}
}

func TestCollector_FIMEventTrigger(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sca_fim_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	bus := pipeline.New()
	sub := bus.Subscribe()
	defer sub.Close()

	cfg := config.SCACollectorConfig{
		Enabled:         true,
		ScanOnStartup:   false,
		ScanOnFIMEvents: true,
		Interval:        0,
		TargetPaths:     []string{tempDir},
	}

	collector := New(cfg, bus, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector.Start(ctx)

	// Write an insecure file
	badFilePath := filepath.Join(tempDir, "sshd_config")
	if err := os.WriteFile(badFilePath, []byte("PermitRootLogin yes\n"), 0644); err != nil {
		t.Fatalf("failed to write test sshd_config: %v", err)
	}

	// Trigger FIM event on bus
	bus.PublishFIM(&audit.FIMEvent{
		Timestamp: time.Now(),
		Op:        "create",
		Path:      badFilePath,
		Hash:      "dummyhash",
	})

	// Expect SCA finding alert on bus
	deadline := time.After(5 * time.Second)
	foundSCA := false
	for !foundSCA {
		select {
		case ev := <-sub.C:
			if ev.Type == pipeline.EventTypeSCA || ev.Type == pipeline.EventTypeAlert {
				foundSCA = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for SCA event after FIM event")
		}
	}
}
