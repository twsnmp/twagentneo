//go:build !windows && !linux

package service

import (
	"errors"
)

var errNotSupported = errors.New("service operations are only supported on Windows and Linux")

// IsWindowsService reports false on non-Windows platforms.
func IsWindowsService() bool {
	return false
}

// Install returns an error on non-Windows platforms.
func Install(opts InstallOptions) error {
	return errNotSupported
}

// Remove returns an error on non-Windows platforms.
func Remove() error {
	return errNotSupported
}

// Start returns an error on non-Windows platforms.
func Start() error {
	return errNotSupported
}

// Stop returns an error on non-Windows platforms.
func Stop() error {
	return errNotSupported
}

// Status returns an error on non-Windows platforms.
func Status() (string, error) {
	return "", errNotSupported
}

// Run returns an error on non-Windows platforms.
func Run(name string, handler ServiceHandler) error {
	return errNotSupported
}
