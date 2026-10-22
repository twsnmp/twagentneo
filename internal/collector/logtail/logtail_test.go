package logtail

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailerSources(t *testing.T) {
	custom := []string{"/var/log/custom.log", "/var/log/app.log"}
	tailer := New(custom)
	srcs := tailer.Sources()
	if len(srcs) != 2 || srcs[0] != custom[0] || srcs[1] != custom[1] {
		t.Fatalf("expected sources %v, got %v", custom, srcs)
	}
}

func TestTailerFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Create file with initial line
	if err := os.WriteFile(logFile, []byte("initial line\n"), 0644); err != nil {
		t.Fatalf("failed to create log file: %v", err)
	}

	tailer := New([]string{logFile})
	tailer.Start()
	defer tailer.Stop()

	// Append a line
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open file for append: %v", err)
	}
	defer f.Close()

	time.Sleep(100 * time.Millisecond)
	if _, err := f.WriteString("second line\n"); err != nil {
		t.Fatalf("failed to write string: %v", err)
	}

	select {
	case ev := <-tailer.Events():
		if ev.Line != "second line" {
			t.Errorf("expected 'second line', got %q", ev.Line)
		}
		if ev.Source != logFile {
			t.Errorf("expected source %q, got %q", logFile, ev.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for log event")
	}
}
