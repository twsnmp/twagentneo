// twagentneo - AI Security Monitoring Agent for TWSNMP NEO
// Collects host resources, network state, file integrity events, and OS logs.
// Evaluates logs through a two-tier Sigma + tensai LLM audit engine.
// Delivers enriched alerts via MQTT, Syslog, and SNMP TRAP.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/audit/aijudge"
	"github.com/twsnmp/twagentneo/internal/audit/sigma"
	"github.com/twsnmp/twagentneo/internal/collector/fim"
	"github.com/twsnmp/twagentneo/internal/collector/logtail"
	"github.com/twsnmp/twagentneo/internal/collector/network"
	"github.com/twsnmp/twagentneo/internal/collector/resource"
	"github.com/twsnmp/twagentneo/internal/config"
	"github.com/twsnmp/twagentneo/internal/exporter"
	"github.com/twsnmp/twagentneo/internal/pipeline"
)

var version = "v0.1.0"

func main() {
	// --- CLI Flags ---
	configPath := flag.String("config", "twagentneo.yaml", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("twagentneo %s %s/%s", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	log.Printf("twagentneo %s starting — os=%s arch=%s", version, runtime.GOOS, runtime.GOARCH)

	// --- Load Configuration ---
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	log.Printf("agent id=%s name=%s", cfg.Agent.ID, cfg.Agent.Name)

	// --- Context for graceful shutdown ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v — shutting down", sig)
		cancel()
	}()

	// --- Internal Event Bus ---
	bus := pipeline.New()
	defer bus.Stop()

	var wg sync.WaitGroup

	// --- Sigma Engine ---
	var sigmaEngine *sigma.Engine
	if cfg.Audit.Sigma.Enabled {
		sigmaEngine, err = sigma.NewEngine()
		if err != nil {
			log.Printf("[sigma] engine init failed: %v (Sigma disabled)", err)
		} else {
			log.Printf("[sigma] loaded %d rules for %s", sigmaEngine.RuleCount(), runtime.GOOS)
		}
	}

	// --- AI Judge ---
	var judge *aijudge.Judge
	if cfg.Audit.AIJudge.Enabled {
		judge, err = aijudge.New(true, cfg.Audit.AIJudge.ModelPath, cfg.Audit.AIJudge.Timeout)
		if err != nil {
			log.Printf("[aijudge] init error: %v", err)
		}
	}
	if judge == nil {
		judge, _ = aijudge.New(false, "", 0)
	}
	defer judge.Close()

	// --- Exporters ---
	var mqttExp *exporter.MQTTExporter
	if cfg.Exporters.MQTT.Enabled {
		mqttExp, err = exporter.NewMQTTExporter(cfg.Exporters.MQTT, cfg.Agent.ID)
		if err != nil {
			log.Printf("[mqtt] exporter init failed: %v", err)
		} else {
			defer mqttExp.Close()
		}
	}

	var syslogExp *exporter.SyslogExporter
	if cfg.Exporters.Syslog.Enabled {
		syslogExp, err = exporter.NewSyslogExporter(cfg.Exporters.Syslog)
		if err != nil {
			log.Printf("[syslog] exporter init failed: %v", err)
		} else {
			defer syslogExp.Close()
		}
	}

	var trapExp *exporter.SNMPTrapExporter
	if cfg.Exporters.SNMPTrap.Enabled {
		trapExp, err = exporter.NewSNMPTrapExporter(cfg.Exporters.SNMPTrap)
		if err != nil {
			log.Printf("[snmptrap] exporter init failed: %v", err)
		} else {
			defer trapExp.Close()
		}
	}

	// --- Event Dispatch Loop ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		runDispatch(ctx, bus, mqttExp, syslogExp, trapExp)
	}()

	// --- Resource Collector ---
	if cfg.Collectors.Resource.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runResourceCollector(ctx, bus, cfg.Collectors.Resource)
		}()
	}

	// --- Network / ARP Collector ---
	if cfg.Collectors.Network.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runNetworkCollector(ctx, bus, cfg.Collectors.Network)
		}()
	}

	// --- FIM Collector ---
	if cfg.Collectors.FIM.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runFIMCollector(ctx, bus, cfg.Collectors.FIM)
		}()
	}

	// --- Log Tailer & Audit Pipeline ---
	if cfg.Collectors.Logs.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLogTailerAndAudit(ctx, bus, sigmaEngine, judge)
		}()
	}

	// --- Heartbeat Ticker ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeat(ctx, bus, cfg.Agent.ID)
	}()

	// Wait for shutdown.
	<-ctx.Done()
	log.Println("twagentneo stopping...")
	wg.Wait()
	log.Println("twagentneo stopped cleanly.")
}

// runDispatch reads events from the bus and routes them to exporters.
func runDispatch(
	ctx context.Context,
	bus *pipeline.Bus,
	mqttExp *exporter.MQTTExporter,
	syslogExp *exporter.SyslogExporter,
	trapExp *exporter.SNMPTrapExporter,
) {
	sub := bus.Subscribe()
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			dispatchEvent(ev, mqttExp, syslogExp, trapExp)
		}
	}
}

func dispatchEvent(
	ev *pipeline.Event,
	mqttExp *exporter.MQTTExporter,
	syslogExp *exporter.SyslogExporter,
	trapExp *exporter.SNMPTrapExporter,
) {
	switch ev.Type {
	case pipeline.EventTypeMetrics:
		if mqttExp != nil {
			if err := mqttExp.PublishMetrics(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt metrics error: %v", err)
			}
		}

	case pipeline.EventTypeNetwork:
		if mqttExp != nil {
			if err := mqttExp.PublishNetwork(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt network error: %v", err)
			}
		}

	case pipeline.EventTypeFIM:
		fimEv, ok := ev.Payload.(*audit.FIMEvent)
		if !ok {
			return
		}
		if mqttExp != nil {
			_ = mqttExp.PublishFIM(fimEv)
		}
		if syslogExp != nil {
			_ = syslogExp.SendFIM(fimEv)
		}
		if trapExp != nil {
			_ = trapExp.SendFIMAlert(fimEv)
		}

	case pipeline.EventTypeAlert:
		alert, ok := ev.Payload.(*audit.SecurityAlert)
		if !ok {
			return
		}
		if mqttExp != nil {
			_ = mqttExp.PublishAlert(alert)
		}
		if syslogExp != nil {
			_ = syslogExp.SendAlert(alert)
		}
		if trapExp != nil {
			_ = trapExp.SendSecurityAlert(alert)
		}

	case pipeline.EventTypeResourceAlert:
		ra, ok := ev.Payload.(*audit.ResourceAlert)
		if !ok {
			return
		}
		if mqttExp != nil {
			_ = mqttExp.PublishResourceAlert(ra)
		}
		if syslogExp != nil {
			_ = syslogExp.SendResourceAlert(ra)
		}
		if trapExp != nil {
			_ = trapExp.SendResourceAlert(ra)
		}

	case pipeline.EventTypeHeartbeat:
		if trapExp != nil {
			_ = trapExp.SendHeartbeat()
		}
		if mqttExp != nil {
			_ = mqttExp.PublishHeartbeat()
		}
	}
}

// runResourceCollector periodically collects host resource metrics and evaluates thresholds.
func runResourceCollector(ctx context.Context, bus *pipeline.Bus, cfg config.ResourceCollectorConfig) {
	collector := resource.New()
	var prev *resource.Metrics
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m, err := collector.Collect(prev)
			if err != nil {
				log.Printf("[resource] collect error: %v", err)
				continue
			}
			prev = m
			bus.PublishMetrics(m)
			checkResourceThresholds(m, cfg, bus)
		}
	}
}

// checkResourceThresholds evaluates measured metrics against configured thresholds.
func checkResourceThresholds(m *resource.Metrics, cfg config.ResourceCollectorConfig, bus *pipeline.Bus) {
	now := time.Now()

	// CPU check
	if cfg.CPUThreshold > 0 && m.CPUPercent >= cfg.CPUThreshold {
		bus.PublishResourceAlert(&audit.ResourceAlert{
			Timestamp: now,
			Resource:  "cpu",
			Threshold: cfg.CPUThreshold,
			Value:     m.CPUPercent,
		})
	}

	// Memory check
	if cfg.MemThreshold > 0 && m.MemPercent >= cfg.MemThreshold {
		bus.PublishResourceAlert(&audit.ResourceAlert{
			Timestamp: now,
			Resource:  "mem",
			Threshold: cfg.MemThreshold,
			Value:     m.MemPercent,
		})
	}

	// Disk check
	if cfg.DiskThreshold > 0 {
		for _, d := range m.Disks {
			if d.UsedPercent >= cfg.DiskThreshold {
				bus.PublishResourceAlert(&audit.ResourceAlert{
					Timestamp: now,
					Resource:  "disk",
					MountPath: d.MountPoint,
					Threshold: cfg.DiskThreshold,
					Value:     d.UsedPercent,
				})
			}
		}
	}

	// Load Average check (Unix)
	if cfg.LoadThreshold > 0 && m.LoadAvg1 >= cfg.LoadThreshold {
		bus.PublishResourceAlert(&audit.ResourceAlert{
			Timestamp: now,
			Resource:  "load",
			Threshold: cfg.LoadThreshold,
			Value:     m.LoadAvg1,
		})
	}
}

// runNetworkCollector periodically collects network and ARP state.
func runNetworkCollector(ctx context.Context, bus *pipeline.Bus, cfg config.NetworkCollectorConfig) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := network.Collect()
			if err != nil {
				log.Printf("[network] collect error: %v", err)
				continue
			}
			bus.PublishNetwork(snap)
		}
	}
}

// runFIMCollector starts the file integrity monitor.
func runFIMCollector(ctx context.Context, bus *pipeline.Bus, cfg config.FIMCollectorConfig) {
	watcher, err := fim.New(cfg.Paths)
	if err != nil {
		log.Printf("[fim] init error: %v", err)
		return
	}
	if err := watcher.Start(); err != nil {
		log.Printf("[fim] start error: %v", err)
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events():
			if !ok {
				return
			}
			bus.PublishFIM(ev)
		}
	}
}

// runLogTailerAndAudit starts tailing OS security logs, runs Sigma Tier-1 matching,
// evaluates candidate alerts with Tier-2 local LLM (AI Judge), and publishes enriched alerts.
func runLogTailerAndAudit(ctx context.Context, bus *pipeline.Bus, sigmaEngine *sigma.Engine, judge *aijudge.Judge) {
	if sigmaEngine == nil {
		log.Println("[audit] sigma engine is not active, skipping log tailing")
		return
	}

	tailer := logtail.New(nil) // nil = use OS defaults
	tailer.Start()
	defer tailer.Stop()

	// Sliding window for recent log context lines (up to 20 lines)
	const maxContextLogs = 20
	var contextHistory []string

	// Asynchronous task queue for AI Judge to avoid blocking log processing
	type judgeTask struct {
		alert       *audit.SecurityAlert
		contextLogs []string
	}
	judgeQueue := make(chan judgeTask, 32)

	var judgeWg sync.WaitGroup
	judgeWg.Add(1)
	go func() {
		defer judgeWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case task, ok := <-judgeQueue:
				if !ok {
					return
				}
				if judge != nil {
					task.alert.AIJudge = judge.Evaluate(task.alert, task.contextLogs)
				}
				bus.PublishAlert(task.alert)
			}
		}
	}()
	defer func() {
		close(judgeQueue)
		judgeWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-tailer.Events():
			if !ok {
				return
			}

			// Update context history
			if len(contextHistory) >= maxContextLogs {
				contextHistory = contextHistory[1:]
			}
			contextHistory = append(contextHistory, ev.Line)

			// Tier-1: Sigma rule evaluation
			matches := sigmaEngine.MatchAll(ev.Line, ev.Timestamp.UnixNano())
			if len(matches) == 0 {
				continue
			}

			matchedData := sigmaEngine.ParseLogData(ev.Line)

			for _, entry := range matches {
				rule := entry.Evaluator.Rule
				cat := rule.Logsource.Category
				if cat == "" {
					cat = rule.Logsource.Product
				}
				if cat == "" {
					cat = "Security"
				}

				alert := &audit.SecurityAlert{
					Timestamp:   ev.Timestamp,
					RuleID:      rule.ID,
					RuleTitle:   rule.Title,
					Level:       rule.Level,
					Category:    cat,
					SourceLog:   ev.Source,
					MatchedData: matchedData,
				}

				// Context snapshot for AI Judge
				ctxCopy := make([]string, len(contextHistory))
				copy(ctxCopy, contextHistory)

				// Queue for Tier-2 AI Judge, or fallback to immediate publish if queue is full
				select {
				case judgeQueue <- judgeTask{alert: alert, contextLogs: ctxCopy}:
				default:
					log.Printf("[audit] judge queue full, emitting rule %s without AI judge", alert.RuleID)
					bus.PublishAlert(alert)
				}
			}
		}
	}
}

// runHeartbeat emits a periodic heartbeat event.
func runHeartbeat(ctx context.Context, bus *pipeline.Bus, agentID string) {
	_ = agentID
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bus.Publish(&pipeline.Event{
				Type:      pipeline.EventTypeHeartbeat,
				Timestamp: time.Now(),
			})
		}
	}
}
