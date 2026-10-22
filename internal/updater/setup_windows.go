//go:build windows

package updater

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"github.com/twsnmp/twagentneo/internal/service"
	"golang.org/x/sys/windows"
)

func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

func restart(exePath string) error {
	// If running as a Windows Service:
	// Do NOT execute currentExe directly because it would become an orphaned
	// non-SCM process while SCM considers the service stopped.
	// Instead, trigger a detached delayed SCM restart command and exit gracefully.
	if service.IsWindowsService() {
		slog.Info("Running as Windows service; scheduling SCM service restart", "service", service.ServiceName)
		restartCmd := fmt.Sprintf("timeout /t 3 /nobreak >nul & sc start %s", service.ServiceName)
		cmd := exec.Command("cmd.exe", "/C", restartCmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to schedule Windows service restart: %w", err)
		}
		slog.Info("Successfully scheduled Windows service restart via SCM helper")
		return nil
	}

	// Regular console / standalone process restart
	args := os.Args[1:]
	cmd := exec.Command(exePath, args...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	setupProcessGroup(cmd)

	slog.Info("Spawning updated twagentneo process", "binary", exePath, "args", args)
	return cmd.Start()
}
