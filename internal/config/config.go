package config

import (
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// AgentConfig holds agent identity configuration.
type AgentConfig struct {
	ID       string `mapstructure:"id"`
	Name     string `mapstructure:"name"`
	LogLevel string `mapstructure:"log_level"`
}

// ResourceCollectorConfig holds configuration for the resource collector.
type ResourceCollectorConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	Interval      time.Duration `mapstructure:"interval"`
	CPUThreshold  float64       `mapstructure:"cpu_threshold"`  // % threshold (0 to disable)
	MemThreshold  float64       `mapstructure:"mem_threshold"`  // % threshold (0 to disable)
	DiskThreshold float64       `mapstructure:"disk_threshold"` // % threshold (0 to disable)
	LoadThreshold float64       `mapstructure:"load_threshold"` // LoadAvg1 threshold (0 to disable)
}

// NetworkCollectorConfig holds configuration for the network/ARP/TCP collector.
type NetworkCollectorConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	ARPWatch bool          `mapstructure:"arp_watch"`
	TCPWatch bool          `mapstructure:"tcp_watch"`
}

// FIMCollectorConfig holds configuration for the file integrity monitor.
type FIMCollectorConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	Paths    []string `mapstructure:"paths"`
	Excludes []string `mapstructure:"excludes"`
}

// LogsCollectorConfig holds configuration for the log tailer.
type LogsCollectorConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Paths   []string `mapstructure:"paths"`
}

// SCACollectorConfig holds configuration for the Security Configuration Assessment collector.
type SCACollectorConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	ScanOnStartup   bool          `mapstructure:"scan_on_startup"`
	ScanOnFIMEvents bool          `mapstructure:"scan_on_fim_events"`
	Interval        time.Duration `mapstructure:"interval"`
	TargetPaths     []string      `mapstructure:"target_paths"`
	MaxFiles        int           `mapstructure:"max_files"`
	MaxFileSize     int64         `mapstructure:"max_file_size"`
}

// CollectorsConfig groups all collector configurations.
type CollectorsConfig struct {
	Resource ResourceCollectorConfig `mapstructure:"resource"`
	Network  NetworkCollectorConfig  `mapstructure:"network"`
	FIM      FIMCollectorConfig      `mapstructure:"fim"`
	Logs     LogsCollectorConfig     `mapstructure:"logs"`
	SCA      SCACollectorConfig      `mapstructure:"sca"`
}

// SigmaConfig holds Sigma rule engine configuration.
type SigmaConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// AIJudgeConfig holds tensai LLM judge configuration.
type AIJudgeConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	ModelPath string        `mapstructure:"model_path"`
	Timeout   time.Duration `mapstructure:"timeout"`
}

// AuditConfig groups audit engine configurations.
type AuditConfig struct {
	Sigma   SigmaConfig   `mapstructure:"sigma"`
	AIJudge AIJudgeConfig `mapstructure:"ai_judge"`
}

// MQTTConfig holds MQTT exporter configuration.
type MQTTConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Broker      string `mapstructure:"broker"`
	ClientID    string `mapstructure:"client_id"`
	TopicPrefix string `mapstructure:"topic_prefix"`
	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"password"`
}

// SyslogConfig holds syslog exporter configuration.
type SyslogConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
	Format   string `mapstructure:"format"`
}

// SNMPV3Config holds SNMPv3 authentication/privacy configuration.
type SNMPV3Config struct {
	User         string `mapstructure:"user"`
	AuthProtocol string `mapstructure:"auth_protocol"`
	AuthPassword string `mapstructure:"auth_password"`
	PrivProtocol string `mapstructure:"priv_protocol"`
	PrivPassword string `mapstructure:"priv_password"`
}

// SNMPTrapConfig holds SNMP trap exporter configuration.
type SNMPTrapConfig struct {
	Enabled   bool         `mapstructure:"enabled"`
	Target    string       `mapstructure:"target"`
	Version   string       `mapstructure:"version"`
	Community string       `mapstructure:"community"`
	V3        SNMPV3Config `mapstructure:"v3"`
}

// ExportersConfig groups all exporter configurations.
type ExportersConfig struct {
	MQTT     MQTTConfig     `mapstructure:"mqtt"`
	Syslog   SyslogConfig   `mapstructure:"syslog"`
	SNMPTrap SNMPTrapConfig `mapstructure:"snmp_trap"`
}

// Config is the top-level agent configuration.
type Config struct {
	Agent      AgentConfig      `mapstructure:"agent"`
	Collectors CollectorsConfig `mapstructure:"collectors"`
	Audit      AuditConfig      `mapstructure:"audit"`
	Exporters  ExportersConfig  `mapstructure:"exporters"`
}

var reEnvVar = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandEnv replaces ${VAR} patterns with environment variable values.
func expandEnv(s string) string {
	return reEnvVar.ReplaceAllStringFunc(s, func(m string) string {
		key := m[2 : len(m)-1]
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		log.Printf("[WARN] environment variable %s not set", key)
		return m
	})
}

// Load reads the configuration file at path and returns a parsed Config.
// Environment variable expansion (${VAR}) is applied to string fields.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Defaults
	v.SetDefault("agent.id", "twagentneo-default")
	v.SetDefault("agent.log_level", "info")
	v.SetDefault("collectors.resource.enabled", true)
	v.SetDefault("collectors.resource.interval", "60s")
	v.SetDefault("collectors.resource.cpu_threshold", 90.0)
	v.SetDefault("collectors.resource.mem_threshold", 90.0)
	v.SetDefault("collectors.resource.disk_threshold", 90.0)
	v.SetDefault("collectors.network.enabled", true)
	v.SetDefault("collectors.network.interval", "180s")
	v.SetDefault("collectors.network.arp_watch", true)
	v.SetDefault("collectors.network.tcp_watch", true)
	v.SetDefault("collectors.fim.enabled", true)
	v.SetDefault("collectors.fim.excludes", []string{"*.tmp", "*~"})
	v.SetDefault("collectors.logs.enabled", true)
	v.SetDefault("collectors.sca.enabled", true)
	v.SetDefault("collectors.sca.scan_on_startup", true)
	v.SetDefault("collectors.sca.scan_on_fim_events", true)
	v.SetDefault("collectors.sca.interval", "0s")
	v.SetDefault("collectors.sca.max_files", 2000)
	v.SetDefault("collectors.sca.max_file_size", int64(1048576))
	v.SetDefault("audit.sigma.enabled", true)
	v.SetDefault("audit.ai_judge.enabled", false)
	v.SetDefault("audit.ai_judge.timeout", "5s")
	v.SetDefault("exporters.mqtt.topic_prefix", "twsnmpneo/agent")

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Expand environment variables in sensitive string fields
	cfg.Agent.ID = expandEnv(cfg.Agent.ID)
	cfg.Exporters.MQTT.Password = expandEnv(cfg.Exporters.MQTT.Password)
	cfg.Exporters.SNMPTrap.V3.AuthPassword = expandEnv(cfg.Exporters.SNMPTrap.V3.AuthPassword)
	cfg.Exporters.SNMPTrap.V3.PrivPassword = expandEnv(cfg.Exporters.SNMPTrap.V3.PrivPassword)

	// Ensure agent ID is non-empty
	if cfg.Agent.ID == "" {
		hostname, _ := os.Hostname()
		cfg.Agent.ID = strings.ReplaceAll(hostname, " ", "-")
	}

	return &cfg, nil
}
