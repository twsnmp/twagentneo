package updater

import (
	"testing"
)

func TestDetectEnvironment(t *testing.T) {
	// Debug detection
	envDebug := DetectEnvironment("dev", "none", false)
	if !envDebug.IsDebug || envDebug.CanSelfUpdate {
		t.Errorf("expected debug env to not allow self update, got %+v", envDebug)
	}

	// Release standalone detection
	envRel := DetectEnvironment("v0.1.0", "abc1234", false)
	if envRel.IsDebug {
		t.Errorf("expected release env not to be debug, got %+v", envRel)
	}
}
