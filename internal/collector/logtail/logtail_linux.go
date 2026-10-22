//go:build linux

package logtail

import (
	"os"
	"syscall"
)

// defaultSources returns Linux security log paths to tail.
// Different Linux distributions use different security log paths
// (e.g. Debian/Ubuntu uses /var/log/auth.log, RHEL/CentOS uses /var/log/secure).
// Only files that actually exist are watched to prevent error spamming.
func defaultSources() []string {
	candidates := []string{
		"/var/log/auth.log", // Debian/Ubuntu
		"/var/log/secure",   // RHEL/CentOS
		"/var/log/syslog",   // Generic syslog
	}
	var sources []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			sources = append(sources, p)
		}
	}
	return sources
}

// inode returns the inode number of the open file.
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
