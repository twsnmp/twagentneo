// twagentneo - AI Security Monitoring Agent for TWSNMP NEO
// Collects host resources, network state, file integrity events, and OS logs.
// Evaluates logs through a two-tier Sigma + tensai LLM audit engine.
// Delivers enriched alerts via MQTT, Syslog, and SNMP TRAP.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
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
	"github.com/twsnmp/twagentneo/internal/service"
	"github.com/twsnmp/twagentneo/internal/updater"
)

var (
	version = "v0.1.0"
	commit  = ""
	date    = "unknown"

	debugEnabled bool
)

func debugLog(format string, v ...any) {
	if debugEnabled {
		log.Printf("[debug] "+format, v...)
	}
}

func init() {
	if version != "" && !strings.HasPrefix(version, "v") && version != "dev" && version != "unknown" {
		version = "v" + version
	}
}

func resolveCommit() string {
	if commit != "" && commit != "none" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				rev := s.Value
				if len(rev) > 7 {
					return rev[:7]
				}
				return rev
			}
		}
	}
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		c := strings.TrimSpace(string(out))
		if c != "" {
			return c
		}
	}
	return "dev"
}

func resolveDate() string {
	if date != "" && date != "unknown" {
		return date
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.time" && s.Value != "" {
				return s.Value
			}
		}
	}
	return "unknown"
}

func printVersion() {
	c := resolveCommit()
	d := resolveDate()
	fmt.Printf("twagentneo %s (commit: %s, built: %s, %s/%s)\n", version, c, d, runtime.GOOS, runtime.GOARCH)
}

func handleUpdateCommand(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "Check for available updates without applying")
	shortCheck := fs.Bool("c", false, "Check for available updates without applying (shorthand)")
	targetVer := fs.String("version", "", "Update to specified release tag (e.g. 'v0.2.0')")
	yesFlag := fs.Bool("yes", false, "Update without confirmation")
	shortYes := fs.Bool("y", false, "Update without confirmation (shorthand)")
	_ = fs.Parse(args)

	isCheck := *checkOnly || *shortCheck
	isYes := *yesFlag || *shortYes

	c := resolveCommit()
	env := updater.DetectEnvironment(version, c, false)

	fmt.Println("=== twagentneo Update Manager ===")
	fmt.Printf("Current Version : %s\n", version)
	fmt.Printf("Git Commit      : %s\n", c)
	fmt.Printf("Environment     : %s\n", env.Description)
	fmt.Println("---------------------------------")

	if !env.CanSelfUpdate {
		fmt.Printf("Notice: %s\n", env.UpdateGuide)
		os.Exit(0)
	}

	upd := updater.New(updater.Config{
		CurrentVersion: version,
		Commit:         c,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Print("Checking for updates on GitHub Releases... ")
	info, err := upd.CheckUpdate(ctx, true)
	if err != nil {
		fmt.Printf("Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Done")

	fmt.Printf("Latest Version  : %s\n", info.LatestVersion)
	if info.PublishedAt.IsZero() {
		fmt.Println("Published At    : unknown")
	} else {
		fmt.Printf("Published At    : %s\n", info.PublishedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if info.ReleaseURL != "" {
		fmt.Printf("Release URL     : %s\n", info.ReleaseURL)
	}

	if isCheck {
		if info.HasUpdate {
			fmt.Printf("\nNew update is available: %s -> %s\n", version, info.LatestVersion)
			fmt.Println("Run 'twagentneo update' to apply the update.")
		} else {
			fmt.Println("\ntwagentneo is already up to date.")
		}
		os.Exit(0)
	}

	if !info.HasUpdate && *targetVer == "" {
		fmt.Println("\ntwagentneo is already up to date. No action needed.")
		os.Exit(0)
	}

	target := info.LatestVersion
	if *targetVer != "" {
		target = *targetVer
		if !strings.HasPrefix(target, "v") {
			target = "v" + target
		}
	}

	if !isYes {
		fmt.Printf("\nDo you want to update twagentneo to %s? [y/N]: ", target)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" && input != "yes" {
			fmt.Println("Update cancelled.")
			os.Exit(0)
		}
	}

	fmt.Printf("\nApplying update to %s...\n", target)
	updateCtx, updateCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer updateCancel()

	if err := upd.RunUpdateDirect(updateCtx, *targetVer); err != nil {
		fmt.Printf("Update failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("twagentneo successfully updated to %s!\n", target)
	fmt.Println("Please restart any running agent services or run 'twagentneo' to start the new binary.")
	os.Exit(0)
}

func handleServiceCommand(action string, remainingArgs []string) {
	switch strings.ToLower(action) {
	case "install":
		var autoStart bool
		var delayedStart bool
		var serviceArgs []string

		for i := 0; i < len(remainingArgs); i++ {
			arg := remainingArgs[i]
			if arg == "-auto" || arg == "--auto" || arg == "-service-auto" || arg == "--service-auto" {
				autoStart = true
			} else if arg == "-delayed" || arg == "--delayed" || arg == "-service-delayed" || arg == "--service-delayed" {
				delayedStart = true
			} else if strings.EqualFold(arg, "install") || strings.EqualFold(arg, "service") {
				continue
			} else {
				serviceArgs = append(serviceArgs, arg)
			}
		}

		err := service.Install(service.InstallOptions{
			AutoStart:    autoStart,
			DelayedStart: delayedStart,
			Arguments:    serviceArgs,
		})
		if err != nil {
			fmt.Printf("Failed to install service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q installed successfully.\n", service.ServiceName)
		if delayedStart {
			fmt.Println("Startup type: Automatic (Delayed Start)")
		} else if autoStart {
			fmt.Println("Startup type: Automatic")
		} else {
			fmt.Println("Startup type: Manual")
		}
		os.Exit(0)

	case "remove", "uninstall":
		if err := service.Remove(); err != nil {
			fmt.Printf("Failed to remove service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q removed successfully.\n", service.ServiceName)
		os.Exit(0)

	case "start":
		if err := service.Start(); err != nil {
			fmt.Printf("Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q started successfully.\n", service.ServiceName)
		os.Exit(0)

	case "stop":
		if err := service.Stop(); err != nil {
			fmt.Printf("Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q stopped successfully.\n", service.ServiceName)
		os.Exit(0)

	case "restart":
		if err := service.Restart(); err != nil {
			fmt.Printf("Failed to restart service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q restarted successfully.\n", service.ServiceName)
		os.Exit(0)

	case "status":
		st, err := service.Status()
		if err != nil {
			fmt.Printf("Failed to query service status: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service %q status: %s\n", service.ServiceName, st)
		os.Exit(0)

	default:
		fmt.Printf("Unknown service command %q. Available commands: install, remove, start, stop, restart, status\n", action)
		os.Exit(1)
	}
}

type serviceRunner struct {
	configPath string
	debugFlag  bool
	cancel     context.CancelFunc
}

func (s *serviceRunner) Start() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("agent runner panic: %v", r)
			log.Printf("[FATAL] %v", err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	return runAgent(ctx, s.configPath, s.debugFlag)
}

func (s *serviceRunner) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func setupServiceLogging(exeDir string) {
	candidates := []string{
		filepath.Join(exeDir, "twagentneo.log"),
		filepath.Join(os.TempDir(), "twagentneo.log"),
	}
	for _, p := range candidates {
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			log.SetOutput(f)
			log.Printf("twagentneo service logging initialized at %s", p)
			return
		}
	}
}

func main() {
	// Subcommand handling
	if len(os.Args) >= 2 {
		subcmd := strings.ToLower(os.Args[1])
		switch subcmd {
		case "version", "-v", "--version":
			printVersion()
			os.Exit(0)
		case "update":
			handleUpdateCommand(os.Args[2:])
			os.Exit(0)
		case "service":
			if len(os.Args) < 3 {
				fmt.Println("Usage: twagentneo service <install|remove|start|stop|restart|status> [options]")
				os.Exit(1)
			}
			action := os.Args[2]
			remaining := os.Args[3:]
			handleServiceCommand(action, remaining)
			return
		case "install", "remove", "uninstall", "start", "stop", "restart", "status":
			handleServiceCommand(subcmd, os.Args[2:])
			return
		}
	}

	// If invoked as a Windows Service by SCM:
	// Adjust current working directory to executable directory to avoid System32 path resolution
	// and configure service file logging.
	if service.IsWindowsService() {
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			_ = os.Chdir(exeDir)
			setupServiceLogging(exeDir)
		}
	}

	// --- CLI Flags ---
	configPath := flag.String("config", "twagentneo.yaml", "path to configuration file")
	var debugFlag bool
	flag.BoolVar(&debugFlag, "debug", false, "enable debug logging to console")
	flag.BoolVar(&debugFlag, "d", false, "enable debug logging to console (shorthand)")
	showVersion := flag.Bool("version", false, "print version and exit")
	updateFlag := flag.Bool("update", false, "Update twagentneo to the latest release")
	checkUpdateFlag := flag.Bool("check-update", false, "Check for available twagentneo updates")

	// Service management flags
	serviceCmd := flag.String("service", "", "Service action for Windows SCM or Linux systemd (install, remove, start, stop, restart, status)")
	serviceAuto := flag.Bool("service-auto", false, "Set service startup type to automatic when installing")
	serviceDelayed := flag.Bool("service-delayed", false, "Set service startup type to automatic (delayed) when installing")

	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	if *updateFlag || *checkUpdateFlag {
		var updateArgs []string
		if *checkUpdateFlag {
			updateArgs = append(updateArgs, "-check")
		}
		handleUpdateCommand(updateArgs)
		os.Exit(0)
	}

	// Resolve configuration file with smart fallback (twagentneo.yaml or config.yaml)
	resolvedConfig := *configPath
	if _, err := os.Stat(resolvedConfig); os.IsNotExist(err) {
		if _, err := os.Stat("twagentneo.yaml"); err == nil {
			resolvedConfig = "twagentneo.yaml"
		} else if _, err := os.Stat("config.yaml"); err == nil {
			resolvedConfig = "config.yaml"
		}
	}

	// Handle flag-based service management: -service <action>
	if *serviceCmd != "" {
		var extraArgs []string
		if *serviceAuto {
			extraArgs = append(extraArgs, "-auto")
		}
		if *serviceDelayed {
			extraArgs = append(extraArgs, "-delayed")
		}
		// Forward any configuration flags passed alongside
		skipNext := false
		for i := 1; i < len(os.Args); i++ {
			arg := os.Args[i]
			if skipNext {
				skipNext = false
				continue
			}
			if arg == "-service" || arg == "--service" {
				skipNext = true
				continue
			}
			if strings.HasPrefix(arg, "-service=") || strings.HasPrefix(arg, "--service=") {
				continue
			}
			if arg == "-service-auto" || arg == "--service-auto" ||
				arg == "-service-delayed" || arg == "--service-delayed" {
				continue
			}
			if strings.EqualFold(arg, *serviceCmd) {
				continue
			}
			extraArgs = append(extraArgs, arg)
		}
		handleServiceCommand(*serviceCmd, extraArgs)
		return
	}

	// If running under Windows Service Control Manager, dispatch to service runner
	if service.IsWindowsService() {
		log.Printf("Starting TWAGENT NEO as Windows Service (%s)", service.ServiceName)
		runner := &serviceRunner{
			configPath: resolvedConfig,
			debugFlag:  debugFlag,
		}
		if err := service.Run(service.ServiceName, runner); err != nil {
			log.Printf("Service execution failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// Standalone interactive execution
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v — shutting down", sig)
		cancel()

		// A second signal forces immediate exit
		sig = <-sigCh
		log.Printf("received second signal %v — forcing exit", sig)
		os.Exit(1)
	}()

	if err := runAgent(ctx, resolvedConfig, debugFlag); err != nil {
		log.Fatalf("twagentneo error: %v", err)
	}
}

func runAgent(ctx context.Context, configPath string, debugFlag bool) error {
	c := resolveCommit()
	log.Printf("twagentneo %s (commit: %s) starting — os=%s arch=%s", version, c, runtime.GOOS, runtime.GOARCH)

	// --- Load Configuration ---
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	if debugFlag || strings.EqualFold(cfg.Agent.LogLevel, "debug") {
		debugEnabled = true
		log.Println("[debug] debug logging enabled")
	}
	log.Printf("agent id=%s name=%s", cfg.Agent.ID, cfg.Agent.Name)
	debugLog("configuration loaded from %s", configPath)

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
	// Subscribe before starting collectors so that immediate startup collections are never dropped.
	sub := bus.Subscribe()
	defer sub.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		runDispatch(ctx, sub, mqttExp, syslogExp, trapExp)
	}()

	// --- Resource Collector ---
	if cfg.Collectors.Resource.Enabled {
		debugLog("starting resource collector (interval: %v)", cfg.Collectors.Resource.Interval)
		wg.Add(1)
		go func() {
			defer wg.Done()
			runResourceCollector(ctx, bus, cfg.Collectors.Resource)
		}()
	}

	// --- Network / ARP Collector ---
	if cfg.Collectors.Network.Enabled {
		debugLog("starting network collector (interval: %v, arp: %v, tcp: %v)",
			cfg.Collectors.Network.Interval, cfg.Collectors.Network.ARPWatch, cfg.Collectors.Network.TCPWatch)
		wg.Add(1)
		go func() {
			defer wg.Done()
			runNetworkCollector(ctx, bus, cfg.Collectors.Network)
		}()
	}

	// --- FIM Collector ---
	if cfg.Collectors.FIM.Enabled {
		debugLog("starting FIM collector (paths: %v)", cfg.Collectors.FIM.Paths)
		wg.Add(1)
		go func() {
			defer wg.Done()
			runFIMCollector(ctx, bus, cfg.Collectors.FIM)
		}()
	}

	// --- Log Tailer & Audit Pipeline ---
	if cfg.Collectors.Logs.Enabled {
		debugLog("starting log tailer & audit pipeline")
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLogTailerAndAudit(ctx, bus, cfg.Collectors.Logs, sigmaEngine, judge)
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

	// Graceful shutdown with timeout protection
	shutdownDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		log.Println("twagentneo stopped cleanly.")
	case <-time.After(5 * time.Second):
		log.Println("[WARN] shutdown timed out after 5s — forcing clean exit")
	}

	return nil
}

// runDispatch reads events from the bus subscription and routes them to exporters.
func runDispatch(
	ctx context.Context,
	sub *pipeline.Sub,
	mqttExp *exporter.MQTTExporter,
	syslogExp *exporter.SyslogExporter,
	trapExp *exporter.SNMPTrapExporter,
) {
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
	debugLog("[dispatch] routing event: type=%s", ev.Type)
	switch ev.Type {
	case pipeline.EventTypeMetrics:
		if mqttExp != nil {
			if err := mqttExp.PublishMetrics(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt metrics error: %v", err)
			} else {
				debugLog("[dispatch] mqtt metrics published")
			}
		}

	case pipeline.EventTypeInterface:
		if mqttExp != nil {
			if err := mqttExp.PublishInterface(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt interface error: %v", err)
			} else {
				debugLog("[dispatch] mqtt interface published")
			}
		}

	case pipeline.EventTypeARP:
		if mqttExp != nil {
			if err := mqttExp.PublishARP(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt arp error: %v", err)
			} else {
				debugLog("[dispatch] mqtt arp published")
			}
		}

	case pipeline.EventTypeTCP:
		if mqttExp != nil {
			if err := mqttExp.PublishTCP(ev.Payload); err != nil {
				log.Printf("[dispatch] mqtt tcp error: %v", err)
			} else {
				debugLog("[dispatch] mqtt tcp published")
			}
		}

	case pipeline.EventTypeFIM:
		fimEv, ok := ev.Payload.(*audit.FIMEvent)
		if !ok {
			return
		}
		log.Printf("[fim] alert: op=%s path=%s hash=%s", fimEv.Op, fimEv.Path, fimEv.Hash)
		if mqttExp != nil {
			_ = mqttExp.PublishFIM(fimEv)
			debugLog("[dispatch] mqtt fim alert published")
		}
		if syslogExp != nil {
			_ = syslogExp.SendFIM(fimEv)
			debugLog("[dispatch] syslog fim alert sent")
		}
		if trapExp != nil {
			_ = trapExp.SendFIMAlert(fimEv)
			debugLog("[dispatch] snmptrap fim alert sent")
		}

	case pipeline.EventTypeAlert:
		alert, ok := ev.Payload.(*audit.SecurityAlert)
		if !ok {
			return
		}
		log.Printf("[alert] sigma alert: rule=%s title=%q level=%s category=%s source=%s",
			alert.RuleID, alert.RuleTitle, alert.Level, alert.Category, alert.SourceLog)
		if alert.AIJudge != nil {
			log.Printf("[alert] ai judge: is_threat=%v compliance_violated=%v summary=%s",
				alert.AIJudge.IsThreat, alert.AIJudge.ComplianceViolated, alert.AIJudge.SummaryJa)
		}
		if mqttExp != nil {
			_ = mqttExp.PublishAlert(alert)
			debugLog("[dispatch] mqtt alert published")
		}
		if syslogExp != nil {
			_ = syslogExp.SendAlert(alert)
			debugLog("[dispatch] syslog alert sent")
		}
		if trapExp != nil {
			_ = trapExp.SendSecurityAlert(alert)
			debugLog("[dispatch] snmptrap alert sent")
		}

	case pipeline.EventTypeResourceAlert:
		ra, ok := ev.Payload.(*audit.ResourceAlert)
		if !ok {
			return
		}
		log.Printf("[alert] resource alert: resource=%s threshold=%.1f value=%.1f mount=%s",
			ra.Resource, ra.Threshold, ra.Value, ra.MountPath)
		if mqttExp != nil {
			_ = mqttExp.PublishResourceAlert(ra)
			debugLog("[dispatch] mqtt resource alert published")
		}
		if syslogExp != nil {
			_ = syslogExp.SendResourceAlert(ra)
			debugLog("[dispatch] syslog resource alert sent")
		}
		if trapExp != nil {
			_ = trapExp.SendResourceAlert(ra)
			debugLog("[dispatch] snmptrap resource alert sent")
		}

	case pipeline.EventTypeHeartbeat:
		if trapExp != nil {
			_ = trapExp.SendHeartbeat()
			debugLog("[dispatch] snmptrap heartbeat sent")
		}
		if mqttExp != nil {
			_ = mqttExp.PublishHeartbeat()
			debugLog("[dispatch] mqtt heartbeat published")
		}
	}
}

// runResourceCollector periodically collects host resource metrics and evaluates thresholds.
func runResourceCollector(ctx context.Context, bus *pipeline.Bus, cfg config.ResourceCollectorConfig) {
	collector := resource.New()
	var prev *resource.Metrics

	collect := func() {
		m, err := collector.Collect(prev)
		if err != nil {
			log.Printf("[resource] collect error: %v", err)
			return
		}
		debugLog("[resource] collect: cpu=%.1f%% mem=%.1f%% load1=%.2f disks=%d ifaces=%d",
			m.CPUPercent, m.MemPercent, m.LoadAvg1, len(m.Disks), len(m.Interfaces))
		prev = m
		bus.PublishMetrics(m)
		checkResourceThresholds(m, cfg, bus)
	}

	// Immediate collection on startup
	collect()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
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

// runNetworkCollector periodically collects network interface, ARP, and TCP connection state.
func runNetworkCollector(ctx context.Context, bus *pipeline.Bus, cfg config.NetworkCollectorConfig) {
	ifaceCollector := network.NewInterfaceCollector()

	collect := func() {
		// 1. Network Interfaces
		ifaces, err := ifaceCollector.Collect()
		if err != nil {
			log.Printf("[network] get interfaces error: %v", err)
		} else {
			debugLog("[network] interfaces collected: count=%d", len(ifaces))
			bus.PublishInterface(ifaces)
		}

		// 2. ARP Watch
		if cfg.ARPWatch {
			arp, err := network.GetARP()
			if err != nil {
				log.Printf("[network] get arp error: %v", err)
			} else {
				debugLog("[network] arp entries collected: count=%d", len(arp))
				bus.PublishARP(arp)
			}
		}

		// 3. TCP Connections Watch
		if cfg.TCPWatch {
			tcpConns, err := network.GetTCPConnections()
			if err != nil {
				log.Printf("[network] get tcp connections error: %v", err)
			} else {
				debugLog("[network] tcp connections collected: count=%d", len(tcpConns))
				bus.PublishTCP(tcpConns)
			}
		}
	}

	// Immediate collection on startup
	collect()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
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
	if err := watcher.Start(ctx); err != nil {
		log.Printf("[fim] start error: %v", err)
		return
	}
	defer watcher.Stop()
	debugLog("[fim] watcher started for %d paths", len(cfg.Paths))

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events():
			if !ok {
				return
			}
			debugLog("[fim] event received: op=%s path=%s", ev.Op, ev.Path)
			bus.PublishFIM(ev)
		}
	}
}

// runLogTailerAndAudit starts tailing OS security logs, runs Sigma Tier-1 matching,
// evaluates candidate alerts with Tier-2 local LLM (AI Judge), and publishes enriched alerts.
func runLogTailerAndAudit(ctx context.Context, bus *pipeline.Bus, cfg config.LogsCollectorConfig, sigmaEngine *sigma.Engine, judge *aijudge.Judge) {
	if sigmaEngine == nil {
		log.Println("[audit] sigma engine is not active, skipping log tailing")
		return
	}

	tailer := logtail.New(cfg.Paths) // nil/empty = use OS defaults
	tailer.Start()
	defer tailer.Stop()
	debugLog("[audit] starting log tailer for sources: %v", tailer.Sources())

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
			debugLog("[audit] scanned log line (source=%s): %s", ev.Source, ev.Line)

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
				debugLog("[audit] sigma match: rule=%s title=%q level=%s", rule.ID, rule.Title, rule.Level)

				// Context snapshot for AI Judge
				ctxCopy := make([]string, len(contextHistory))
				copy(ctxCopy, contextHistory)

				// Queue for Tier-2 AI Judge, or fallback to immediate publish if queue is full
				select {
				case judgeQueue <- judgeTask{alert: alert, contextLogs: ctxCopy}:
					debugLog("[audit] queued alert for AI judge: rule=%s", alert.RuleID)
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
			debugLog("[heartbeat] periodic heartbeat triggered")
			bus.Publish(&pipeline.Event{
				Type:      pipeline.EventTypeHeartbeat,
				Timestamp: time.Now(),
			})
		}
	}
}
