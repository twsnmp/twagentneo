package updater

import (
	"os"
	"path/filepath"
	"strings"
)

// EnvironmentType represents how twagentneo is executed and managed
type EnvironmentType string

const (
	EnvHomebrew  EnvironmentType = "homebrew"
	EnvCurl      EnvironmentType = "curl"
	EnvDebug     EnvironmentType = "debug"
	EnvContainer EnvironmentType = "container"
)

// EnvironmentInfo holds detected environment characteristics and update instructions
type EnvironmentInfo struct {
	Type          EnvironmentType `json:"type"`
	IsHomebrew    bool            `json:"is_homebrew"`
	IsDebug       bool            `json:"is_debug"`
	IsContainer   bool            `json:"is_container"`
	CanSelfUpdate bool            `json:"can_self_update"`
	UpdateGuide   string          `json:"update_guide"`
	Description   string          `json:"description"`
}

// IsHomebrew returns true if the current executable is located within a Homebrew or Linuxbrew hierarchy
func IsHomebrew() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	realExe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		realExe = exe
	}

	cleanReal := filepath.ToSlash(strings.ToLower(realExe))
	cleanExe := filepath.ToSlash(strings.ToLower(exe))

	for _, p := range []string{cleanExe, cleanReal} {
		if strings.Contains(p, "/cellar/") ||
			strings.Contains(p, "/opt/homebrew/") ||
			strings.Contains(p, "/home/linuxbrew/") ||
			strings.Contains(p, "/.linuxbrew/") {
			return true
		}
	}

	if prefix := os.Getenv("HOMEBREW_PREFIX"); prefix != "" {
		cleanPrefix := filepath.ToSlash(strings.ToLower(prefix))
		if strings.HasPrefix(cleanReal, cleanPrefix) || strings.HasPrefix(cleanExe, cleanPrefix) {
			return true
		}
	}

	return false
}

// DetectEnvironment determines the execution environment based on filesystem paths, container flags, and version string
func DetectEnvironment(version string, commit string, isDebug bool) EnvironmentInfo {
	if isDebug || version == "dev" || strings.Contains(version, "debug") || commit == "dev" {
		return EnvironmentInfo{
			Type:          EnvDebug,
			IsDebug:       true,
			CanSelfUpdate: false,
			UpdateGuide:   "twagentneo is running from source or debug build. Rebuild via 'mise run build' or git pull.",
			Description:   "Development / Debug Build",
		}
	}

	if IsContainer() {
		return EnvironmentInfo{
			Type:          EnvContainer,
			IsContainer:   true,
			CanSelfUpdate: false,
			UpdateGuide:   "twagentneo is running inside a container. Pull the latest container image instead.",
			Description:   "Container (Docker / Podman / K8s)",
		}
	}

	if IsHomebrew() {
		return EnvironmentInfo{
			Type:          EnvHomebrew,
			IsHomebrew:    true,
			CanSelfUpdate: false,
			UpdateGuide:   "twagentneo is installed via Homebrew. Run 'brew update && brew upgrade twagentneo' to update.",
			Description:   "Homebrew Package",
		}
	}

	return EnvironmentInfo{
		Type:          EnvCurl,
		CanSelfUpdate: true,
		UpdateGuide:   "Run 'twagentneo update' to automatically update to the latest release.",
		Description:   "Standalone Binary",
	}
}
