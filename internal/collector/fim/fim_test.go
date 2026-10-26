package fim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/twsnmp/twagentneo/internal/audit"
)

func TestHandleEventTimestamp(t *testing.T) {
	w := &Watcher{
		eventCh: make(chan *audit.FIMEvent, 10),
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	before := time.Now().UTC().Add(-time.Second)
	w.handleEvent(fsnotify.Event{
		Name: testFile,
		Op:   fsnotify.Create,
	})
	after := time.Now().UTC().Add(time.Second)

	select {
	case ev := <-w.Events():
		if ev.Timestamp.IsZero() {
			t.Errorf("expected non-zero timestamp, got %v", ev.Timestamp)
		}
		if ev.Timestamp.Before(before) || ev.Timestamp.After(after) {
			t.Errorf("timestamp %v out of expected range [%v, %v]", ev.Timestamp, before, after)
		}
		if ev.Op != "create" {
			t.Errorf("expected op 'create', got %q", ev.Op)
		}
		if ev.Path != testFile {
			t.Errorf("expected path %q, got %q", testFile, ev.Path)
		}
		if ev.Hash == "" {
			t.Errorf("expected non-empty sha256 hash for created file")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestWatcherIntegration(t *testing.T) {
	dir := t.TempDir()
	w, err := New([]string{dir}, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer w.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Create a file in watched directory
	testFile := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	select {
	case ev := <-w.Events():
		if ev.Timestamp.IsZero() {
			t.Errorf("expected non-zero timestamp, got %v", ev.Timestamp)
		}
		if ev.Path != testFile {
			t.Errorf("expected path %s, got %s", testFile, ev.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FIM event")
	}
}

func TestWatcherExcludes(t *testing.T) {
	dir := t.TempDir()
	// Watch dir, exclude *.tmp and *~
	w, err := New([]string{dir}, []string{"*.tmp", "*~"})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer w.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// 1. Create excluded .tmp file
	tmpFile := filepath.Join(dir, "hosts.tmp")
	if err := os.WriteFile(tmpFile, []byte("temp"), 0644); err != nil {
		t.Fatalf("failed to create tmp file: %v", err)
	}

	// 2. Create excluded backup file
	backupFile := filepath.Join(dir, "hosts~")
	if err := os.WriteFile(backupFile, []byte("backup"), 0644); err != nil {
		t.Fatalf("failed to create backup file: %v", err)
	}

	// 3. Create non-excluded normal file
	normalFile := filepath.Join(dir, "hosts")
	if err := os.WriteFile(normalFile, []byte("127.0.0.1 localhost"), 0644); err != nil {
		t.Fatalf("failed to create normal file: %v", err)
	}

	// The first received event should be normalFile (tmpFile and backupFile should be filtered out)
	select {
	case ev := <-w.Events():
		if ev.Path != normalFile {
			t.Errorf("expected event for %s, got %s", normalFile, ev.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FIM event")
	}

	// Ensure no events for tmp or backup files were emitted
	for {
		select {
		case ev := <-w.Events():
			if ev.Path == tmpFile || ev.Path == backupFile {
				t.Errorf("unexpected event received for excluded file: %s", ev.Path)
			}
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}

func TestCompileExcludePattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"*.tmp", "hosts.tmp", true},
		{"*.tmp", "/etc/hosts.tmp", true},
		{"*.tmp", `C:\Windows\System32\drivers\etc\hosts.tmp`, true},
		{"*.tmp", "sample.txt", false},
		{"*.tmp", "sample.tmp.bak", false},
		{"*~", "/etc/hosts~", true},
		{"*~", "hosts", false},
		{"hosts.tmp", `C:\Windows\System32\drivers\etc\hosts.tmp`, true},
		{"drivers/etc/*.tmp", `C:\Windows\System32\drivers\etc\hosts.tmp`, true},
		{"drivers/etc/*.tmp", `/usr/local/drivers/etc/test.tmp`, true},
		{"drivers/etc/*.tmp", `/var/log/test.tmp`, false},
	}

	for _, tt := range tests {
		re, err := compileExcludePattern(tt.pattern)
		if err != nil {
			t.Fatalf("compileExcludePattern(%q) error: %v", tt.pattern, err)
		}
		if re == nil {
			t.Fatalf("compileExcludePattern(%q) returned nil regex", tt.pattern)
		}
		normPath := normalizePath(tt.path)
		got := re.MatchString(normPath)
		if got != tt.match {
			t.Errorf("pattern %q on path %q (norm: %q): got %v, want %v", tt.pattern, tt.path, normPath, got, tt.match)
		}
	}
}
