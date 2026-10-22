// Package exporter provides multi-protocol delivery of metrics and alerts.
package exporter

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/config"
)

// MQTTExporter publishes metrics and alerts to an MQTT broker.
type MQTTExporter struct {
	cfg     config.MQTTConfig
	agentID string
	client  mqtt.Client
}

// heartbeatPayload is the online/offline status payload.
type heartbeatPayload struct {
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// NewMQTTExporter creates and connects an MQTTExporter.
func NewMQTTExporter(cfg config.MQTTConfig, agentID string) (*MQTTExporter, error) {
	e := &MQTTExporter{cfg: cfg, agentID: agentID}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.Broker)
	opts.SetClientID(cfg.ClientID)
	opts.SetAutoReconnect(true)
	opts.SetCleanSession(true)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)

	if cfg.Username != "" {
		opts.SetUsername(cfg.Username)
	}
	if cfg.Password != "" {
		opts.SetPassword(cfg.Password)
	}

	// TLS configuration for tls:// or ssl:// broker URLs.
	if strings.HasPrefix(cfg.Broker, "tls://") || strings.HasPrefix(cfg.Broker, "ssl://") {
		opts.SetTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	}

	// Last Will and Testament — published when agent disconnects unexpectedly.
	lwtTopic := e.topic("status")
	lwtPayload, _ := json.Marshal(heartbeatPayload{
		AgentID:   agentID,
		Status:    "offline",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	opts.SetBinaryWill(lwtTopic, lwtPayload, 1, true)

	opts.OnConnect = func(_ mqtt.Client) {
		log.Printf("[mqtt] connected to %s", cfg.Broker)
		// Publish online status on (re)connect.
		e.publishStatus("online")
	}
	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		log.Printf("[mqtt] connection lost: %v", err)
	}

	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("mqtt connect: %w", err)
	}
	e.client = client
	return e, nil
}

// topic builds a full MQTT topic from a suffix.
func (e *MQTTExporter) topic(suffix string) string {
	return fmt.Sprintf("%s/%s/%s", e.cfg.TopicPrefix, e.agentID, suffix)
}

// publish marshals v to JSON and publishes it on the given topic.
func (e *MQTTExporter) publish(topic string, qos byte, retained bool, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	token := e.client.Publish(topic, qos, retained, data)
	token.Wait()
	return token.Error()
}

// PublishMetrics sends host resource metrics.
func (e *MQTTExporter) PublishMetrics(payload interface{}) error {
	return e.publish(e.topic("metrics"), 0, false, payload)
}

// PublishInterface sends network interface configuration and counters.
func (e *MQTTExporter) PublishInterface(payload interface{}) error {
	return e.publish(e.topic("interface"), 0, false, payload)
}

// PublishTCP sends active TCP connection destination data.
func (e *MQTTExporter) PublishTCP(payload interface{}) error {
	return e.publish(e.topic("tcp"), 0, false, payload)
}

// PublishARP sends ARP watch table data.
func (e *MQTTExporter) PublishARP(payload interface{}) error {
	return e.publish(e.topic("arp"), 0, false, payload)
}

// PublishAlert sends a security alert (Sigma + optional AI judge).
func (e *MQTTExporter) PublishAlert(alert *audit.SecurityAlert) error {
	return e.publish(e.topic("alert"), 1, false, alert)
}

// PublishFIM sends a file integrity monitoring event.
func (e *MQTTExporter) PublishFIM(ev *audit.FIMEvent) error {
	return e.publish(e.topic("alert"), 1, false, ev)
}

// PublishResourceAlert sends a host resource threshold alert.
func (e *MQTTExporter) PublishResourceAlert(ra *audit.ResourceAlert) error {
	return e.publish(e.topic("alert"), 1, false, ra)
}

// PublishHeartbeat sends a periodic keep-alive status.
func (e *MQTTExporter) PublishHeartbeat() error {
	return e.publishStatus("online")
}

func (e *MQTTExporter) publishStatus(status string) error {
	payload := heartbeatPayload{
		AgentID:   e.agentID,
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	return e.publish(e.topic("status"), 1, true, payload)
}

// Close disconnects the MQTT client gracefully.
func (e *MQTTExporter) Close() {
	_ = e.publishStatus("offline")
	e.client.Disconnect(500)
}
