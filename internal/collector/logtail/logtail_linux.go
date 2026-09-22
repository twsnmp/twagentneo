//go:build linux

package logtail

import (
	"os"
	"syscall"
)

// defaultSources returns Linux security log paths to tail.
func defaultSources() []string {
	// Try common paths; missing files are handled gracefully by the tailer.
	return []string{
		"/var/log/auth.log",  // Debian/Ubuntu
		"/var/log/secure",    // RHEL/CentOS
		"/var/log/syslog",
	}
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
