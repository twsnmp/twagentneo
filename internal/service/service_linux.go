//go:build linux

package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	systemdUnitDir = "/etc/systemd/system"
	runCmd         = defaultRunCmd
)

func defaultRunCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if errStr != "" {
			return out, fmt.Errorf("%s: %s", err, errStr)
		}
		return out, err
	}
	return out, nil
}

// IsWindowsService reports false on Linux.
func IsWindowsService() bool {
	return false
}

func checkSystemd() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl command not found (systemd is required)")
	}
	return nil
}

func checkRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges required to manage systemd service (please run with sudo)")
	}
	return nil
}

func formatServiceArgs(args []string) []string {
	var serviceArgs []string
	for _, arg := range args {
		if strings.EqualFold(arg, "install") || strings.EqualFold(arg, "service") {
			continue
		}
		serviceArgs = append(serviceArgs, arg)
	}

	for i := 0; i < len(serviceArgs); i++ {
		arg := serviceArgs[i]
		if (arg == "-config" || arg == "--config") && i+1 < len(serviceArgs) {
			absPath, absErr := filepath.Abs(serviceArgs[i+1])
			if absErr == nil {
				serviceArgs[i+1] = absPath
			}
		} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
			parts := strings.SplitN(arg, "=", 2)
			absPath, absErr := filepath.Abs(parts[1])
			if absErr == nil {
				serviceArgs[i] = parts[0] + "=" + absPath
			}
		}
	}
	return serviceArgs
}

func generateUnitContent(execPath string, args []string, workDir string) string {
	var execStart strings.Builder
	execStart.WriteString(execPath)
	for _, arg := range args {
		execStart.WriteString(" ")
		if strings.ContainsAny(arg, " \t\n\"") {
			execStart.WriteString(fmt.Sprintf("%q", arg))
		} else {
			execStart.WriteString(arg)
		}
	}

	return fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://github.com/twsnmp/twagentneo
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
WorkingDirectory=%s
Restart=always
RestartSec=5s
LimitNOFILE=65536
KillMode=process
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
`, ServiceDescription, execStart.String(), workDir)
}

// Install installs the application as a systemd service.
func Install(opts InstallOptions) error {
	if err := checkSystemd(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("service %q is already installed at %s", ServiceName, unitPath)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute executable path: %w", err)
	}

	workDir := filepath.Dir(exePath)
	args := formatServiceArgs(opts.Arguments)
	content := generateUnitContent(exePath, args, workDir)

	if err := os.MkdirAll(systemdUnitDir, 0755); err != nil {
		return fmt.Errorf("failed to create systemd unit directory: %w", err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service unit file: %w", err)
	}

	if _, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	if opts.AutoStart || opts.DelayedStart {
		if _, err := runCmd("systemctl", "enable", ServiceName+".service"); err != nil {
			return fmt.Errorf("failed to enable service autostart: %w", err)
		}
	}

	return nil
}

// Remove uninstalls the systemd service.
func Remove() error {
	if err := checkSystemd(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return fmt.Errorf("service %q is not installed", ServiceName)
	}

	// Stop and disable service (ignore errors if service is not running or already disabled)
	_, _ = runCmd("systemctl", "stop", ServiceName+".service")
	_, _ = runCmd("systemctl", "disable", ServiceName+".service")

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service unit file: %w", err)
	}

	_, _ = runCmd("systemctl", "daemon-reload")
	_, _ = runCmd("systemctl", "reset-failed", ServiceName+".service")

	return nil
}

// Start starts the systemd service.
func Start() error {
	if err := checkSystemd(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return fmt.Errorf("service %q is not installed", ServiceName)
	}

	if _, err := runCmd("systemctl", "start", ServiceName+".service"); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	return nil
}

// Stop stops the systemd service.
func Stop() error {
	if err := checkSystemd(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return fmt.Errorf("service %q is not installed", ServiceName)
	}

	if _, err := runCmd("systemctl", "stop", ServiceName+".service"); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	return nil
}

// Restart restarts the systemd service.
func Restart() error {
	if err := checkSystemd(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return fmt.Errorf("service %q is not installed", ServiceName)
	}

	if _, err := runCmd("systemctl", "restart", ServiceName+".service"); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}
	return nil
}

// Status queries the status of the systemd service.
func Status() (string, error) {
	if err := checkSystemd(); err != nil {
		return "", err
	}

	unitPath := filepath.Join(systemdUnitDir, ServiceName+".service")
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return "Not Installed", nil
	}

	activeOut, _ := runCmd("systemctl", "is-active", ServiceName+".service")
	enabledOut, _ := runCmd("systemctl", "is-enabled", ServiceName+".service")

	active := strings.TrimSpace(activeOut)
	enabled := strings.TrimSpace(enabledOut)

	switch active {
	case "active":
		if enabled == "enabled" {
			return "Running (Automatic)", nil
		}
		return "Running (Manual)", nil
	case "inactive":
		if enabled == "enabled" {
			return "Stopped (Automatic)", nil
		}
		return "Stopped (Manual)", nil
	case "failed":
		return "Failed", nil
	case "":
		return "Unknown", nil
	default:
		if enabled != "" {
			return fmt.Sprintf("%s (%s)", active, enabled), nil
		}
		return active, nil
	}
}

// Run executes the service under systemd (simple background execution).
func Run(name string, handler ServiceHandler) error {
	return handler.Start()
}
