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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

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

// defaultExcludes returns commonly ignored temporary file patterns.
func defaultExcludes() []string {
	return []string{
		"*.tmp",
		"*~",
	}
}

// Watcher wraps fsnotify and emits audit.FIMEvent on changes.
type Watcher struct {
	watcher          *fsnotify.Watcher
	paths            []string
	excludes         []string
	compiledExcludes []*regexp.Regexp
	eventCh          chan *audit.FIMEvent
	done             chan struct{}
	once             sync.Once
}

// New creates a FIM Watcher. If paths is empty, the OS-appropriate defaults are used.
// If excludes is nil, defaultExcludes() (*.tmp, *~) is used. Pass an empty slice to disable exclusions.
func New(paths []string, excludes []string) (*Watcher, error) {
	if len(paths) == 0 {
		paths = defaultPaths()
	}
	if excludes == nil {
		excludes = defaultExcludes()
	}
	var compiled []*regexp.Regexp
	for _, p := range excludes {
		re, err := compileExcludePattern(p)
		if err != nil {
			log.Printf("[fim] invalid exclude pattern %q: %v", p, err)
			continue
		}
		if re != nil {
			compiled = append(compiled, re)
		}
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fim: create watcher: %w", err)
	}
	w := &Watcher{
		watcher:          fw,
		paths:            paths,
		excludes:         excludes,
		compiledExcludes: compiled,
		eventCh:          make(chan *audit.FIMEvent, 512),
		done:             make(chan struct{}),
	}
	return w, nil
}

// normalizePath converts both Windows and Unix backslashes/slashes to a clean forward-slash path.
func normalizePath(path string) string {
	cleaned := filepath.Clean(strings.ReplaceAll(path, `\`, "/"))
	return strings.ReplaceAll(cleaned, `\`, "/")
}

// compileExcludePattern converts a glob-like pattern (*, **, ?) to a compiled regexp.
func compileExcludePattern(pattern string) (*regexp.Regexp, error) {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return nil, nil
	}
	pattern = strings.ReplaceAll(trimmed, `\`, "/")
	var b strings.Builder
	if runtime.GOOS == "windows" {
		b.WriteString("(?i)")
	}

	hasSlash := strings.Contains(pattern, "/")
	if !hasSlash {
		b.WriteString("(?:^|/)")
	} else if !strings.HasPrefix(pattern, "/") && !strings.Contains(pattern, ":/") {
		b.WriteString("(?:^|.*/)")
	} else {
		b.WriteString("^")
	}

	i := 0
	n := len(pattern)
	for i < n {
		if i+1 < n && pattern[i:i+2] == "**" {
			b.WriteString(".*")
			i += 2
			if i < n && pattern[i] == '/' {
				b.WriteString("(?:/.*)?")
				i++
			}
			continue
		}
		switch pattern[i] {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '{', '}', '[', ']', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteByte(pattern[i])
		default:
			b.WriteByte(pattern[i])
		}
		i++
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// isExcluded returns true if path matches any compiled exclude regex.
func (w *Watcher) isExcluded(path string) bool {
	if len(w.compiledExcludes) == 0 {
		return false
	}
	normalized := normalizePath(path)
	for _, re := range w.compiledExcludes {
		if re != nil && re.MatchString(normalized) {
			return true
		}
	}
	return false
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
		if err := addRecursive(ctx, w.watcher, p, w.done, w.isExcluded); err != nil {
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
	if w.isExcluded(ev.Name) {
		return
	}
	op := fsnotifyOpToStr(ev.Op)
	if op == "" {
		return
	}

	fev := &audit.FIMEvent{
		Timestamp: time.Now().UTC(),
		Op:        op,
		Path:      ev.Name,
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
func addRecursive(ctx context.Context, fw *fsnotify.Watcher, root string, done chan struct{}, isExcluded func(string) bool) error {
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
		if isExcluded != nil && isExcluded(p) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
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
