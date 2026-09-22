// Package logtail provides real-time OS security log collection with
// automatic rotation tracking. Collected log lines are forwarded to the
// Sigma evaluation pipeline.
package logtail

import (
	"bufio"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogEvent is a single log line collected from an OS log source.
type LogEvent struct {
	Timestamp time.Time
	Source    string // e.g. "/var/log/auth.log" or "WindowsEventLog"
	Line      string // raw log line
}

// Tailer follows one or more log files, emitting LogEvent values.
// It handles log rotation by detecting file truncation or inode changes.
type Tailer struct {
	sources []string
	eventCh chan *LogEvent
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// New creates a Tailer. If sources is empty, OS-appropriate defaults are used.
func New(sources []string) *Tailer {
	if len(sources) == 0 {
		sources = defaultSources()
	}
	return &Tailer{
		sources: sources,
		eventCh: make(chan *LogEvent, 4096),
		done:    make(chan struct{}),
	}
}

// Start begins following all configured sources.
func (t *Tailer) Start() {
	for _, src := range t.sources {
		t.wg.Add(1)
		go t.tailFile(src)
	}
}

// Stop halts all tailers.
func (t *Tailer) Stop() {
	t.once.Do(func() {
		close(t.done)
	})
	t.wg.Wait()
}

// Events returns the read-only channel of log events.
func (t *Tailer) Events() <-chan *LogEvent {
	return t.eventCh
}

// tailFile reads a single file from its current end, emitting new lines.
// It reopens the file when it detects a rotation (truncation or new inode).
func (t *Tailer) tailFile(path string) {
	defer t.wg.Done()

	var f *os.File
	var prevInode uint64
	var offset int64

	openFile := func() bool {
		var err error
		f, err = os.Open(path)
		if err != nil {
			log.Printf("[logtail] cannot open %s: %v", path, err)
			return false
		}
		// Seek to end on first open to avoid replaying old entries.
		size, _ := f.Seek(0, io.SeekEnd)
		offset = size
		prevInode = inode(f)
		return true
	}

	if !openFile() {
		// File not yet available. Log once, then retry silently.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		retries := 0
		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				retries++
				if openFile() {
					goto tail
				}
				// Log every 12 retries (~1 min) to show we are still waiting,
				// but not every 5 seconds as that floods the console.
				if retries%12 == 0 {
					log.Printf("[logtail] still waiting for %s (%dm elapsed)", path, retries*5/60)
				}
			}
		}
	}

tail:
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			// Check for rotation
			if rotated(path, prevInode) {
				f.Close()
				if !openFile() {
					continue
				}
				reader = bufio.NewReader(f)
			}

			// Read all available lines
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					offset += int64(len(line))
					ev := &LogEvent{
						Timestamp: time.Now(),
						Source:    path,
						Line:      trimNewline(line),
					}
					select {
					case t.eventCh <- ev:
					default:
						log.Printf("[logtail] event channel full, dropping line from %s", path)
					}
				}
				if err != nil {
					break // io.EOF — wait for more data
				}
			}
		}
	}
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
