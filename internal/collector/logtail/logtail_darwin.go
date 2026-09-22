//go:build darwin

package logtail

import (
	"os"
	"syscall"
)

// defaultSources returns macOS log paths to tail.
// macOS does not provide /var/log/auth.log or /var/log/system.log by default
// (the OS uses Apple System Log / Unified Logging). We watch only the files
// that actually exist. Non-existent paths are silently skipped.
func defaultSources() []string {
	candidates := []string{
		"/var/log/install.log",    // package installer events
		"/var/log/system.log",     // older macOS / syslog-compatible daemons
		"/private/var/log/apache2/access_log", // apache (if installed)
		"/private/var/log/apache2/error_log",
	}
	// Filter to files that exist so logtail never spams errors for
	// paths that are simply absent on modern macOS.
	var sources []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			sources = append(sources, p)
		}
	}
	return sources
}

// inode returns the inode number of the open file on macOS.
func inode(f *os.File) uint64 {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return 0
	}
	return st.Ino
}

// rotated returns true if the file at path has been replaced (different inode).
func rotated(path string, prevInode uint64) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	return st.Ino != prevInode
}
