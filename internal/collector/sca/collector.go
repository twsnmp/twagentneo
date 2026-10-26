package sca

import (
	"context"
	"log"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
	"github.com/twsnmp/twagentneo/internal/audit/aijudge"
	"github.com/twsnmp/twagentneo/internal/config"
	"github.com/twsnmp/twagentneo/internal/pipeline"
)

// Collector coordinates local configuration assessments across startup, periodic intervals,
// and real-time FIM event triggers.
type Collector struct {
	cfg     config.SCACollectorConfig
	bus     *pipeline.Bus
	auditor *Auditor
	judge   *aijudge.Judge
}

// New creates an SCA Collector.
func New(cfg config.SCACollectorConfig, bus *pipeline.Bus, judge *aijudge.Judge) *Collector {
	return &Collector{
		cfg:     cfg,
		bus:     bus,
		auditor: NewAuditor(cfg.MaxFiles, cfg.MaxFileSize),
		judge:   judge,
	}
}

// Start launches the SCA collector loops.
func (c *Collector) Start(ctx context.Context) {
	targetPaths := c.cfg.TargetPaths
	if len(targetPaths) == 0 {
		targetPaths = []string{"/etc"}
	}

	// 1. Baseline scan on startup
	if c.cfg.ScanOnStartup {
		go func() {
			log.Printf("[sca] running startup baseline scan across %v", targetPaths)
			for _, p := range targetPaths {
				select {
				case <-ctx.Done():
					return
				default:
				}
				findings, err := c.auditor.ScanDirectory(ctx, p)
				if err != nil {
					log.Printf("[sca] scan error on %s: %v", p, err)
					continue
				}
				c.emitFindings(findings)
			}
			log.Println("[sca] startup baseline scan completed")
		}()
	}

	// 2. FIM-driven real-time auditing
	if c.cfg.ScanOnFIMEvents && c.bus != nil {
		sub := c.bus.Subscribe()
		go c.watchFIMEvents(ctx, sub)
	}

	// 3. Periodic scan (if interval > 0)
	if c.cfg.Interval > 0 {
		go func() {
			ticker := time.NewTicker(c.cfg.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log.Println("[sca] running periodic full scan")
					for _, p := range targetPaths {
						findings, err := c.auditor.ScanDirectory(ctx, p)
						if err != nil {
							log.Printf("[sca] periodic scan error on %s: %v", p, err)
							continue
						}
						c.emitFindings(findings)
					}
				}
			}
		}()
	}
}

// watchFIMEvents listens to FIM bus events and triggers immediate scans on created/modified/chmod files.
func (c *Collector) watchFIMEvents(ctx context.Context, sub *pipeline.Sub) {
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			if ev.Type != pipeline.EventTypeFIM {
				continue
			}

			fimEv, ok := ev.Payload.(*audit.FIMEvent)
			if !ok || fimEv == nil {
				continue
			}

			// Only audit on create, write, or chmod operations
			if fimEv.Op != "create" && fimEv.Op != "write" && fimEv.Op != "chmod" {
				continue
			}

			findings, err := c.auditor.ScanFile(fimEv.Path)
			if err != nil {
				continue
			}
			if len(findings) > 0 {
				log.Printf("[sca] FIM-triggered scan on %s found %d issues", fimEv.Path, len(findings))
				c.emitFindings(findings)
			}
		}
	}
}

// emitFindings processes findings, optionally enriches with AI Judge, and publishes them.
func (c *Collector) emitFindings(findings []*audit.SCAFinding) {
	for _, f := range findings {
		alert := f.ToSecurityAlert()

		// If AI Judge is available and finding is high or critical severity, request LLM triage
		if c.judge != nil && (f.Severity == "high" || f.Severity == "critical") {
			aiResult := c.judge.Evaluate(alert, []string{f.Proof, f.Description})
			if aiResult != nil {
				alert.AIJudge = aiResult
				f.AIJudge = aiResult
			}
		}

		if c.bus != nil {
			c.bus.PublishSCA(f)
			c.bus.PublishAlert(alert)
		}
	}
}
