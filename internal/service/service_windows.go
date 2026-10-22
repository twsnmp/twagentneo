//go:build windows

package service

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsWindowsService reports whether the current process is running as a Windows service.
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

// formatServiceArgs formats arguments and converts relative file paths to absolute paths.
func formatServiceArgs(args []string) []string {
	serviceArgs := make([]string, len(args))
	copy(serviceArgs, args)

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

// Install installs the application as a Windows service.
func Install(opts InstallOptions) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %q is already installed", ServiceName)
	}

	startType := mgr.StartManual
	if opts.AutoStart || opts.DelayedStart {
		startType = mgr.StartAutomatic
	}

	serviceArgs := formatServiceArgs(opts.Arguments)

	cfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        uint32(startType),
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		DelayedAutoStart: opts.DelayedStart,
	}

	s, err = m.CreateService(ServiceName, exePath, cfg, serviceArgs...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	return nil
}

// Remove uninstalls the Windows service.
func Remove() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop service first if running
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		// Wait for stop up to 10 seconds
		timeout := time.Now().Add(10 * time.Second)
		for time.Now().Before(timeout) {
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	return nil
}

// Start starts the installed Windows service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}
	if status.State == svc.Running {
		return fmt.Errorf("service %q is already running", ServiceName)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	// Wait up to 10 seconds for service to enter Running state
	timeout := time.Now().Add(10 * time.Second)
	for time.Now().Before(timeout) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err == nil && status.State == svc.Running {
			return nil
		}
	}

	return nil
}

// Stop stops the running Windows service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}
	if status.State == svc.Stopped {
		return fmt.Errorf("service %q is already stopped", ServiceName)
	}

	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to send stop command: %w", err)
	}

	// Wait up to 10 seconds for service to enter Stopped state
	timeout := time.Now().Add(10 * time.Second)
	for time.Now().Before(timeout) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err == nil && status.State == svc.Stopped {
			return nil
		}
	}

	return nil
}

// Restart restarts the Windows service by stopping and then starting it.
func Restart() error {
	_ = Stop()
	return Start()
}

// Status returns human-readable status of the service.
func Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "Not Installed", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %w", err)
	}

	switch status.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Start Pending", nil
	case svc.StopPending:
		return "Stop Pending", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continue Pending", nil
	case svc.PausePending:
		return "Pause Pending", nil
	case svc.Paused:
		return "Paused", nil
	default:
		return fmt.Sprintf("Unknown state (%d)", status.State), nil
	}
}

type winService struct {
	handler ServiceHandler
}

func (w *winService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Start agent handler asynchronously
	errCh := make(chan error, 1)
	go func() {
		errCh <- w.handler.Start()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				log.Printf("Windows service execution error: %v", err)
			}
			changes <- svc.Status{State: svc.StopPending}
			_ = w.handler.Stop()
			changes <- svc.Status{State: svc.Stopped}
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				_ = w.handler.Stop()
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				log.Printf("Unexpected control request: %v", c.Cmd)
			}
		}
	}
}

// Run executes the service under Windows Service Control Manager.
func Run(name string, handler ServiceHandler) error {
	if handler == nil {
		return errors.New("nil service handler")
	}
	return svc.Run(name, &winService{handler: handler})
}
