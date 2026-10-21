//go:build windows

package updater

import (
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

func restart(exePath string) error {
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
