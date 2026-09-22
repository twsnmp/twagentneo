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
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

// NetworkCollectorConfig holds configuration for the network/ARP collector.
type NetworkCollectorConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	ARPWatch bool          `mapstructure:"arp_watch"`
}

// FIMCollectorConfig holds configuration for the file integrity monitor.
type FIMCollectorConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Paths   []string `mapstructure:"paths"`
}

// LogsCollectorConfig holds configuration for the log tailer.
type LogsCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// CollectorsConfig groups all collector configurations.
type CollectorsConfig struct {
	Resource ResourceCollectorConfig `mapstructure:"resource"`
	Network  NetworkCollectorConfig  `mapstructure:"network"`
	FIM      FIMCollectorConfig      `mapstructure:"fim"`
	Logs     LogsCollectorConfig     `mapstructure:"logs"`
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
	v.SetDefault("collectors.network.enabled", true)
	v.SetDefault("collectors.network.interval", "180s")
	v.SetDefault("collectors.network.arp_watch", true)
	v.SetDefault("collectors.fim.enabled", true)
	v.SetDefault("collectors.logs.enabled", true)
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
