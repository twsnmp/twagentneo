package service

// Service constants
const (
	ServiceName        = "twagentneo"
	ServiceDisplayName = "TWAGENT NEO Service"
	ServiceDescription = "TWAGENT NEO AI Security Monitoring Agent"
)

// InstallOptions holds options for installing the service (Windows SCM or Linux systemd).
type InstallOptions struct {
	AutoStart    bool     // If true, start automatically on system boot
	DelayedStart bool     // If true, start with delayed automatic start
	Arguments    []string // Extra CLI flags/arguments to pass to the service binary
}

// ServiceHandler defines the interface for running the application under the service manager.
type ServiceHandler interface {
	Start() error
	Stop() error
}
