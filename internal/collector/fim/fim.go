// Package fim provides File Integrity Monitoring using OS-native filesystem events.
// It watches configured paths for create / write / remove / chmod / rename operations
// and emits audit.FIMEvent values.
package fim

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/twsnmp/twagentneo/internal/audit"
)

// defaultPaths returns the list of monitored paths for the current OS.
func defaultPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Windows\System32\drivers\etc`,
			`C:\Windows\System32\wbem`,
			`C:\Windows\System32\WindowsPowerShell\v1.0`,
		}
	case "darwin":
		return []string{
			"/etc",
			"/usr/local/bin",
			"/Library/LaunchDaemons",
		}
	default: // linux
		return []string{
			"/etc",
			"/usr/bin",
			"/usr/sbin",
			"/bin",
			"/sbin",
		}
	}
}

// Watcher wraps fsnotify and emits audit.FIMEvent on changes.
type Watcher struct {
	watcher *fsnotify.Watcher
	paths   []string
	eventCh chan *audit.FIMEvent
	done    chan struct{}
	once    sync.Once
}

// New creates a FIM Watcher. If paths is empty, the OS-appropriate defaults are used.
func New(paths []string) (*Watcher, error) {
	if len(paths) == 0 {
		paths = defaultPaths()
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fim: create watcher: %w", err)
	}
	w := &Watcher{
		watcher: fw,
		paths:   paths,
		eventCh: make(chan *audit.FIMEvent, 512),
		done:    make(chan struct{}),
	}
	return w, nil
}

const (
	maxWatchDirs  = 1024
	maxWatchDepth = 4
)

// Start begins watching. Emitted events are sent to Events().
func (w *Watcher) Start(ctx context.Context) error {
	for _, p := range w.paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.done:
			return nil
		default:
		}

		// Check if the root path itself is accessible before walking.
		if _, err := os.Stat(p); err != nil {
			log.Printf("[fim] skipping %s: %v", p, err)
			continue
		}
		// Walk subdirectories to add recursive watches.
		// Permission-denied on sub-directories is silently skipped.
		if err := addRecursive(ctx, w.watcher, p, w.done); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("[fim] warning: cannot watch %s: %v", p, err)
		}
	}
	go w.loop()
	return nil
}

// Stop halts the Watcher.
func (w *Watcher) Stop() {
	w.once.Do(func() {
		close(w.done)
		w.watcher.Close()
	})
}

// Events returns the read-only channel of FIM events.
func (w *Watcher) Events() <-chan *audit.FIMEvent {
	return w.eventCh
}

func (w *Watcher) loop() {
	for {
		select {
		case <-w.done:
			return
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(ev)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[fim] watcher error: %v", err)
		}
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	op := fsnotifyOpToStr(ev.Op)
	if op == "" {
		return
	}

	fev := &audit.FIMEvent{
		Op:   op,
		Path: ev.Name,
	}

	// Compute SHA-256 for create/write operations.
	if op == "create" || op == "write" {
		fev.Hash = sha256File(ev.Name)
	}

	// If a new directory was created, add it to the watcher.
	if op == "create" {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			_ = w.watcher.Add(ev.Name)
		}
	}

	select {
	case w.eventCh <- fev:
	default:
		log.Printf("[fim] event channel full, dropping event for %s", ev.Name)
	}
}

func fsnotifyOpToStr(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "create"
	case op&fsnotify.Write != 0:
		return "write"
	case op&fsnotify.Remove != 0:
		return "remove"
	case op&fsnotify.Rename != 0:
		return "rename"
	case op&fsnotify.Chmod != 0:
		return "chmod"
	}
	return ""
}

// sha256File computes the SHA-256 digest of a file, returning the hex string.
// Returns empty string on error.
func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// addRecursive recursively adds path and all readable sub-directories to watcher.
// Subdirectories that are not accessible due to permission are skipped silently.
// Supports cancellation via ctx and done channel, with depth and count limits.
func addRecursive(ctx context.Context, fw *fsnotify.Watcher, root string, done chan struct{}) error {
	count := 0
	cleanRoot := filepath.Clean(root)
	rootDepth := strings.Count(cleanRoot, string(filepath.Separator))

	return filepath.WalkDir(cleanRoot, func(p string, d os.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return filepath.SkipAll
		default:
		}

		if err != nil {
			// Permission denied on a sub-dir: skip it without reporting.
			if os.IsPermission(err) {
				return filepath.SkipDir
			}
			return nil // other errors also skipped
		}
		if d.IsDir() {
			currentDepth := strings.Count(p, string(filepath.Separator)) - rootDepth
			if currentDepth > maxWatchDepth {
				return filepath.SkipDir
			}

			if count >= maxWatchDirs {
				log.Printf("[fim] directory limit (%d) reached for %s, skipping remaining subdirectories", maxWatchDirs, root)
				return filepath.SkipDir
			}

			if addErr := fw.Add(p); addErr != nil {
				if os.IsPermission(addErr) {
					return filepath.SkipDir
				}
				// Log unexpected errors but don't abort the whole walk.
				log.Printf("[fim] cannot add watch for %s: %v", p, addErr)
			} else {
				count++
			}
		}
		return nil
	})
}
