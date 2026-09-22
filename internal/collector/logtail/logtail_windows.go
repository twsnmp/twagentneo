//go:build windows

package logtail

import "os"

// defaultSources returns Windows Event Log sources.
// On Windows we use Windows Event Log API (see logtail_windows_evtlog.go);
// this stub satisfies the interface for the file-based tailer.
// The event log reader is started separately by the agent main.
func defaultSources() []string {
	// Placeholder: Windows security events are collected via EvtSubscribe,
	// not file tailing. Return empty so the file tailer does nothing on Windows.
	return []string{}
}

// inode always returns 0 on Windows (no POSIX inode concept).
func inode(_ *os.File) uint64 {
	return 0
}

// rotated returns false on Windows: file-based rotation is not used.
func rotated(_ string, _ uint64) bool {
	return false
}
