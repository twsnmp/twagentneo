// Package sigma provides an OS-adaptive Sigma rule evaluation engine for twagentneo.
// It is ported from twsla/pkg/sigma and extended with runtime.GOOS-based rule loading.
package sigma

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	gosigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/elastic/go-grok"
	"gopkg.in/yaml.v3"
)

// SigmaRuleEntry wraps a compiled Sigma rule evaluator with metadata.
type SigmaRuleEntry struct {
	Evaluator   *evaluator.RuleEvaluator
	Source      string // "embed:linux/..." | "embed:windows/..." | "file:..."
	Path        string
	Correlation *CorrelationConfig
}

// Engine holds compiled rules and evaluation state.
type Engine struct {
	sync.RWMutex
	RuleEntries         []*SigmaRuleEntry
	Evaluators          []*evaluator.RuleEvaluator
	SigmaConfigMap      map[string]*gosigma.Config
	NamedCaptureRegList []*regexp.Regexp
	GrokList            []*grok.Grok
	CorrelationTracker  *CorrelationTracker

	// osLabel is the runtime.GOOS value used during rule loading ("linux", "windows", "darwin").
	osLabel string
}

var (
	regJSON    = regexp.MustCompile(`^\s*\{.*\}\s*$`)
	regSplunk  = regexp.MustCompile(`\s*([a-zA-Z_]+[a-zA-Z0-9_]*)=([^ ,;\r\n]+)`)
	regexpGrok = regexp.MustCompile(`%\{.+\}`)

	wazuhLinuxDecoders = []string{
		`Accepted \S+ for (?P<user>\S+) from (?P<client>\S+) port (?P<srcport>\d+)`,
		`Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<client>\S+) port (?P<srcport>\d+)`,
		`(?P<user>\S+) : (?:TTY=\S+ ; )?(?:PWD=\S+ ; )?USER=(?P<dstuser>\S+) ; COMMAND=(?P<command>.+)`,
		`pam_\S+\(sshd:auth\): authentication failure; .*user=(?P<user>\S+)`,
	}
)

// NewEngine creates and initializes a new Sigma Engine.
// Rules are loaded from the embedded FS for the current OS (runtime.GOOS).
func NewEngine() (*Engine, error) {
	eng := &Engine{
		SigmaConfigMap:      make(map[string]*gosigma.Config),
		NamedCaptureRegList: []*regexp.Regexp{},
		GrokList:            []*grok.Grok{},
		CorrelationTracker:  NewCorrelationTracker(),
		osLabel:             runtime.GOOS,
	}

	eng.loadConfigs()
	eng.loadWazuhDecoders()
	if err := eng.loadRules(); err != nil {
		return nil, err
	}
	log.Printf("[sigma] engine ready: os=%s rules=%d", eng.osLabel, len(eng.Evaluators))
	return eng, nil
}

// loadConfigs loads embedded sigma field-mapping configs.
func (e *Engine) loadConfigs() {
	ForEachSigmaConfig(func(k string, d []byte) {
		c, err := gosigma.ParseConfig(d)
		if err != nil {
			log.Printf("[sigma] config parse error %s: %v", k, err)
			return
		}
		e.SigmaConfigMap[k] = &c
	})
}

// getSigmaConfig returns the best matching config for a rule's logsource.
func (e *Engine) getSigmaConfig(r *gosigma.Rule) *gosigma.Config {
	keys := []string{
		r.Logsource.Product + "_" + r.Logsource.Category + "_" + r.Logsource.Service,
		r.Logsource.Product + "_" + r.Logsource.Category,
		r.Logsource.Product,
	}
	for _, k := range keys {
		if conf, ok := e.SigmaConfigMap[k]; ok {
			return conf
		}
	}
	return nil
}

// loadWazuhDecoders adds Wazuh-specific named-capture patterns for Linux log decoding.
func (e *Engine) loadWazuhDecoders() {
	if e.osLabel != "linux" {
		return
	}
	for _, pat := range wazuhLinuxDecoders {
		if r, err := regexp.Compile(pat); err == nil {
			e.NamedCaptureRegList = append(e.NamedCaptureRegList, r)
		}
	}
}

// loadRules loads OS-specific embedded Sigma rules.
func (e *Engine) loadRules() error {
	ruleMap := make(map[string]*SigmaRuleEntry)
	var orderedIDs []string

	ForEachOSSigmaRules(e.osLabel, func(c []byte, path, source string) {
		rule, err := gosigma.ParseRule(c)
		if err != nil && strings.Contains(err.Error(), "'*'") {
			rule, err = autoFixSigmaRule(c, rule)
		}
		// Skip rules that use unsupported keywords.
		for _, s := range rule.Detection.Searches {
			if len(s.Keywords) > 0 {
				err = fmt.Errorf("keywords not supported")
				break
			}
		}
		if err != nil {
			log.Printf("[sigma] skip rule %s: %v", path, err)
			return
		}
		if rule.ID == "" {
			rule.ID = path
		}

		corr := ParseCorrelationConfig(rule.AdditionalFields["correlation"])
		conf := e.getSigmaConfig(&rule)
		var ev *evaluator.RuleEvaluator
		if conf != nil {
			ev = evaluator.ForRule(rule, evaluator.WithConfig(*conf), evaluator.CaseSensitive)
		} else {
			ev = evaluator.ForRule(rule, evaluator.CaseSensitive)
		}

		entry := &SigmaRuleEntry{Evaluator: ev, Source: source, Path: path, Correlation: corr}
		if _, exists := ruleMap[rule.ID]; !exists {
			ruleMap[rule.ID] = entry
			orderedIDs = append(orderedIDs, rule.ID)
		}
	})

	e.RuleEntries = make([]*SigmaRuleEntry, 0, len(orderedIDs))
	e.Evaluators = make([]*evaluator.RuleEvaluator, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		entry := ruleMap[id]
		e.RuleEntries = append(e.RuleEntries, entry)
		e.Evaluators = append(e.Evaluators, entry.Evaluator)
	}
	return nil
}

// ParseLogData parses a log string into structured fields for Sigma evaluation.
// Supports JSON, key=value (Splunk style), named capture regexps, and Grok patterns.
func (e *Engine) ParseLogData(logStr string) map[string]interface{} {
	var data map[string]interface{}

	if err := json.Unmarshal([]byte(logStr), &data); err != nil {
		data = map[string]interface{}{
			"content": logStr,
			"message": logStr,
		}
	}
	if data == nil {
		data = make(map[string]interface{})
	}

	rawText := ""
	if v, ok := data["content"]; ok {
		if s, ok := v.(string); ok {
			rawText = s
		}
	} else if v, ok := data["message"]; ok {
		if s, ok := v.(string); ok {
			rawText = s
		}
	}

	if rawText != "" {
		notJSON := true
		if regJSON.MatchString(rawText) {
			var tmp map[string]interface{}
			if err := json.Unmarshal([]byte(rawText), &tmp); err == nil {
				notJSON = false
				for k, v := range tmp {
					data[k] = v
				}
			}
		}
		if notJSON {
			// key=value parsing
			for _, m := range regSplunk.FindAllStringSubmatch(rawText, -1) {
				if len(m) > 2 {
					if f, err := strconv.ParseFloat(m[2], 64); err == nil {
						data[m[1]] = f
					} else {
						data[m[1]] = m[2]
					}
				}
			}
			// Named capture regexps
			for _, r := range e.NamedCaptureRegList {
				if match := r.FindStringSubmatch(rawText); match != nil {
					for i, k := range r.SubexpNames() {
						if i != 0 && k != "" {
							if f, err := strconv.ParseFloat(match[i], 64); err == nil {
								data[k] = f
							} else {
								data[k] = match[i]
							}
						}
					}
				}
			}
			// Grok patterns
			for _, gr := range e.GrokList {
				if tmp, err := gr.ParseString(rawText); err == nil {
					for k, v := range tmp {
						data[k] = v
					}
				}
			}
		}
	}
	return data
}

// Match evaluates logStr against all loaded rules and returns the first match,
// or nil if no rule matches.
func (e *Engine) Match(logStr string, timeNano int64) *SigmaRuleEntry {
	data := e.ParseLogData(logStr)
	if data == nil {
		return nil
	}
	ctx := context.Background()
	for _, entry := range e.RuleEntries {
		res, err := entry.Evaluator.Matches(ctx, data)
		if err != nil || !res.Match {
			continue
		}
		if entry.Correlation != nil {
			groupVal := extractGroupKey(data, entry.Correlation.GroupBy)
			if !e.CorrelationTracker.RecordAndCheck(entry.Evaluator.Rule.ID, groupVal, timeNano, entry.Correlation) {
				continue
			}
		}
		return entry
	}
	return nil
}

// MatchAll evaluates logStr against all loaded rules and returns all matches.
func (e *Engine) MatchAll(logStr string, timeNano int64) []*SigmaRuleEntry {
	data := e.ParseLogData(logStr)
	if data == nil {
		return nil
	}
	var matched []*SigmaRuleEntry
	ctx := context.Background()
	for _, entry := range e.RuleEntries {
		res, err := entry.Evaluator.Matches(ctx, data)
		if err != nil || !res.Match {
			continue
		}
		if entry.Correlation != nil {
			groupVal := extractGroupKey(data, entry.Correlation.GroupBy)
			if !e.CorrelationTracker.RecordAndCheck(entry.Evaluator.Rule.ID, groupVal, timeNano, entry.Correlation) {
				continue
			}
		}
		matched = append(matched, entry)
	}
	return matched
}

func extractGroupKey(data map[string]interface{}, groupBy []string) string {
	var parts []string
	for _, k := range groupBy {
		if v, ok := data[k]; ok && v != nil {
			parts = append(parts, fmt.Sprintf("%v", v))
		}
	}
	if len(parts) == 0 {
		for _, k := range []string{"client", "srcip"} {
			if v, ok := data[k]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
		}
		return "all"
	}
	return strings.Join(parts, "/")
}

// autoFixSigmaRule attempts to repair rules that use numeric detection keys.
func autoFixSigmaRule(c []byte, r gosigma.Rule) (gosigma.Rule, error) {
	var rule map[string]interface{}
	if err := yaml.Unmarshal(c, &rule); err != nil {
		return r, err
	}
	numReg := regexp.MustCompile(`\d+`)
	replaceMap := make(map[string]string)
	keys := []string{}
	for k, v := range rule {
		if k == "detection" {
			if m, ok := v.(map[string]interface{}); ok {
				for dk, dv := range m {
					if dk == "condition" {
						if cs, ok := dv.(string); ok {
							a := []string{}
							for _, f := range strings.Fields(cs) {
								if f != "1" && numReg.MatchString(f) {
									f = convertNumberToAlpha(f)
								}
								a = append(a, f)
							}
							replaceMap[cs] = strings.Join(a, " ")
							keys = append(keys, cs)
						}
					} else if numReg.MatchString(dk) {
						replaceMap[dk] = convertNumberToAlpha(dk)
						keys = append(keys, dk)
					}
				}
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	s := string(c)
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, replaceMap[k])
	}
	return gosigma.ParseRule([]byte(s))
}

func convertNumberToAlpha(input string) string {
	numToAlpha := map[rune]rune{
		'0': 'a', '1': 'b', '2': 'c', '3': 'd', '4': 'e',
		'5': 'f', '6': 'g', '7': 'h', '8': 'i', '9': 'j',
	}
	var b strings.Builder
	for _, ch := range input {
		if r, ok := numToAlpha[ch]; ok {
			b.WriteRune(r)
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int {
	return len(e.Evaluators)
}

// ResetCorrelation clears correlation tracking state.
func (e *Engine) ResetCorrelation() {
	e.CorrelationTracker.Reset()
}

// keep os import usage even when os isn't directly referenced in this file
var _ = os.Getenv
