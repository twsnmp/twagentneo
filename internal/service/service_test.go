package service

import (
	"runtime"
	"testing"
)

func TestServiceUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		t.Skip("Skipping unsupported platform test on windows/linux")
	}

	if IsWindowsService() {
		t.Errorf("expected IsWindowsService() to be false on %s", runtime.GOOS)
	}

	if err := Install(InstallOptions{}); err == nil {
		t.Errorf("expected Install() to return error on %s", runtime.GOOS)
	}

	if err := Remove(); err == nil {
		t.Errorf("expected Remove() to return error on %s", runtime.GOOS)
	}

	if err := Start(); err == nil {
		t.Errorf("expected Start() to return error on %s", runtime.GOOS)
	}

	if err := Stop(); err == nil {
		t.Errorf("expected Stop() to return error on %s", runtime.GOOS)
	}

	if _, err := Status(); err == nil {
		t.Errorf("expected Status() to return error on %s", runtime.GOOS)
	}

	if err := Run("twagentneo", nil); err == nil {
		t.Errorf("expected Run() to return error on %s", runtime.GOOS)
	}
}
