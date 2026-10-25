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
	w, err := New([]string{dir})
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
