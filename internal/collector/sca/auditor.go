// Package sca provides Security Configuration Assessment (SCA) auditing for local
// configuration files, file permissions, leftover temporary files, and exposed plaintext secrets.
package sca

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/twsnmp/twagentneo/internal/audit"
)

// Auditor inspects directories and files for security configuration flaws and risks.
type Auditor struct {
	MaxFiles    int
	MaxFileSize int64
}

// NewAuditor creates an Auditor with sensible defaults.
func NewAuditor(maxFiles int, maxFileSize int64) *Auditor {
	if maxFiles <= 0 {
		maxFiles = 2000
	}
	if maxFileSize <= 0 {
		maxFileSize = 1024 * 1024 // 1MB
	}
	return &Auditor{
		MaxFiles:    maxFiles,
		MaxFileSize: maxFileSize,
	}
}

// Ignored folders and binary extensions
var (
	ignoredDirs = map[string]bool{
		".git":        true,
		"node_modules": true,
		"vendor":      true,
		"dist":        true,
		"build":       true,
		".vscode":     true,
		".idea":       true,
		"__pycache__": true,
	}

	binaryExts = map[string]bool{
		".exe":    true,
		".dll":    true,
		".so":     true,
		".dylib":  true,
		".png":    true,
		".jpg":    true,
		".jpeg":   true,
		".gif":    true,
		".ico":    true,
		".pdf":    true,
		".zip":    true,
		".gz":     true,
		".tar":    true,
		".tgz":    true,
		".dmg":    true,
		".pkg":    true,
		".class":  true,
		".jar":    true,
		".war":    true,
		".db":     true,
		".sqlite": true,
	}
)

type secretRule struct {
	name        string
	regex       *regexp.Regexp
	severity    string
	description string
	remediation string
}

// secretRules contains regular expressions for hardcoded credentials.
var secretRules = []secretRule{
	{
		name:        "AWS Access Key ID",
		regex:       regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		severity:    "high",
		description: "AWS Access Key ID found in plaintext. If exposed, attackers could gain unauthorized access to cloud resources.",
		remediation: "Revoke the exposed key in AWS IAM and store credentials in secure secret managers or environment variables.",
	},
	{
		name:        "Slack Webhook",
		regex:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		severity:    "medium",
		description: "Slack Incoming Webhook URL found. Attackers could spam Slack channels or extract workspace info.",
		remediation: "Revoke the Slack webhook URL and inject it via environment variables or secret vaults.",
	},
	{
		name:        "Private Key",
		regex:       regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		severity:    "critical",
		description: "Unencrypted private key block found. Private keys must be kept secure and never exposed.",
		remediation: "Ensure strict permissions (0600) or move keys to a secure hardware token / key manager.",
	},
	{
		name:        "Database Connection String Password",
		regex:       regexp.MustCompile(`(?i)(?:db_password|password|db_pass|database_url)\s*[:=]\s*['\"][A-Za-z0-9_\-!@#\$%\^&\*\(\)\+]{4,}['\"]`),
		severity:    "medium",
		description: "A potential database password or credentials assignment was found in plaintext.",
		remediation: "Store database credentials in environment variables or external secret management systems.",
	},
}

// ScanFile audits a single file (ideal for FIM event-driven triggers).
func (a *Auditor) ScanFile(path string) ([]*audit.SCAFinding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, nil
	}

	var findings []*audit.SCAFinding
	a.auditSingleFile(path, info.Name(), info, &findings)
	return findings, nil
}

// ScanDirectory traverses a directory recursively and audits files up to MaxFiles.
func (a *Auditor) ScanDirectory(ctx context.Context, targetDir string) ([]*audit.SCAFinding, error) {
	var findings []*audit.SCAFinding
	fileCount := 0

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // ignore inaccessible directories/files gracefully
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if fileCount >= a.MaxFiles {
			return filepath.SkipDir
		}
		fileCount++

		info, err := d.Info()
		if err != nil {
			return nil
		}

		a.auditSingleFile(path, d.Name(), info, &findings)
		return nil
	})

	return findings, err
}

func (a *Auditor) auditSingleFile(path string, name string, info os.FileInfo, findings *[]*audit.SCAFinding) {
	ext := strings.ToLower(filepath.Ext(path))
	now := time.Now()

	// 1. Audit filename/extension (CIS-4.7: Leftover & Unnecessary Files)
	if ext == ".bak" || ext == ".old" || ext == ".temp" || ext == ".tmp" || strings.HasSuffix(name, "~") {
		*findings = append(*findings, &audit.SCAFinding{
			Timestamp:   now,
			RuleID:      "CIS-4.7",
			Title:       "Leftover Backup or Temporary File",
			Description: fmt.Sprintf("Backup or temporary file '%s' detected. These files often contain sensitive historical data and should be cleaned up.", name),
			Severity:    "low",
			FilePath:    path,
			Proof:       fmt.Sprintf("Filename: %s", name),
			Remediation: fmt.Sprintf("Remove or archive the temporary/backup file '%s'.", path),
			Compliance:  []string{"CIS", "CIS-4.7"},
		})
	}

	// 2. Audit file permissions (CIS-3.14: Access Control & Permissions)
	if runtime.GOOS != "windows" && info != nil {
		mode := info.Mode()

		// World-writable check (0002)
		if mode&0002 != 0 {
			*findings = append(*findings, &audit.SCAFinding{
				Timestamp:   now,
				RuleID:      "CIS-3.14",
				Title:       "World-Writable File",
				Description: fmt.Sprintf("The file '%s' has world-writable permissions (%04o). Any local user or system process can modify its contents.", name, mode.Perm()),
				Severity:    "medium",
				FilePath:    path,
				Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
				Remediation: fmt.Sprintf("Run 'chmod o-w %s' to remove world-writable permissions.", path),
				Compliance:  []string{"CIS", "CIS-3.14"},
			})
		}

		// Loose permissions on private keys or environment files (0044: group/other readable)
		isSensitiveFile := ext == ".pem" || ext == ".key" || name == "id_rsa" || name == ".env"
		if isSensitiveFile && (mode&0044 != 0) {
			*findings = append(*findings, &audit.SCAFinding{
				Timestamp:   now,
				RuleID:      "CIS-3.14",
				Title:       "Loose Permissions on Sensitive File",
				Description: fmt.Sprintf("Sensitive file '%s' is readable by group or others (permissions: %04o). It should be restricted to owner-only access (0600 or 0400).", name, mode.Perm()),
				Severity:    "high",
				FilePath:    path,
				Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
				Remediation: fmt.Sprintf("Run 'chmod 600 %s' to restrict permissions to the owner.", path),
				Compliance:  []string{"CIS", "CIS-3.14"},
			})
		}

		// Critical OS shadow file
		if name == "shadow" && strings.Contains(path, "/etc") {
			if mode&0044 != 0 {
				*findings = append(*findings, &audit.SCAFinding{
					Timestamp:   now,
					RuleID:      "CIS-3.14",
					Title:       "Unsecured Shadow File",
					Description: "The /etc/shadow file containing hashed user passwords has loose read permissions. It must be accessible only by root (0600 or 0000).",
					Severity:    "critical",
					FilePath:    path,
					Proof:       fmt.Sprintf("Permissions: %04o", mode.Perm()),
					Remediation: fmt.Sprintf("Run 'chmod 600 %s' and verify root ownership.", path),
					Compliance:  []string{"CIS", "CIS-3.14"},
				})
			}
		}
	}

	// 3. Skip binary or oversized files for content scanning
	if binaryExts[ext] || (info != nil && info.Size() > a.MaxFileSize) {
		return
	}

	// 4. Content audit (secrets, sshd_config, sysctl.conf)
	a.auditFileContent(path, name, findings)
}

func (a *Auditor) auditFileContent(path string, filename string, findings *[]*audit.SCAFinding) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	reader := io.LimitReader(file, a.MaxFileSize)
	scanner := bufio.NewScanner(reader)

	isSSHConfig := filename == "sshd_config" || strings.HasSuffix(path, "sshd_config")
	isSysctlConfig := filename == "sysctl.conf" || strings.HasSuffix(path, "sysctl.conf")
	now := time.Now()

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// A. Check for hardcoded secrets (CIS-3.12)
		for _, rule := range secretRules {
			if rule.regex.MatchString(line) {
				matched := rule.regex.FindString(line)
				redacted := matched
				if len(matched) > 8 {
					redacted = matched[:4] + "..." + matched[len(matched)-4:]
				}

				*findings = append(*findings, &audit.SCAFinding{
					Timestamp:   now,
					RuleID:      "CIS-3.12",
					Title:       fmt.Sprintf("Hardcoded %s", rule.name),
					Description: rule.description,
					Severity:    rule.severity,
					FilePath:    path,
					Proof:       fmt.Sprintf("Line %d: found pattern '%s'", lineNum, redacted),
					Remediation: rule.remediation,
					Compliance:  []string{"CIS", "CIS-3.12"},
				})
			}
		}

		// B. Check SSH Configuration (CIS-4.1 / CIS-4.8)
		if isSSHConfig {
			cleanLine := strings.TrimSpace(line)
			if cleanLine != "" && !strings.HasPrefix(cleanLine, "#") {
				parts := strings.Fields(cleanLine)
				if len(parts) >= 2 {
					key := strings.ToLower(parts[0])
					val := strings.ToLower(parts[1])

					if key == "permitrootlogin" && val == "yes" {
						*findings = append(*findings, &audit.SCAFinding{
							Timestamp:   now,
							RuleID:      "CIS-4.1",
							Title:       "SSH Root Login Enabled",
							Description: "Allowing direct SSH root login increases the risk of brute-force attacks on the root account. It is recommended to set 'PermitRootLogin no' or restrict it to keys-only.",
							Severity:    "high",
							FilePath:    path,
							Proof:       fmt.Sprintf("Line %d: PermitRootLogin %s", lineNum, parts[1]),
							Remediation: "Set 'PermitRootLogin no' in sshd_config and restart sshd.",
							Compliance:  []string{"CIS", "CIS-4.1"},
						})
					}
					if key == "passwordauthentication" && val == "yes" {
						*findings = append(*findings, &audit.SCAFinding{
							Timestamp:   now,
							RuleID:      "CIS-4.8",
							Title:       "SSH Password Authentication Enabled",
							Description: "Password authentication is active for SSH. Standard practice recommends key-based authentication only to prevent credential brute-forcing.",
							Severity:    "medium",
							FilePath:    path,
							Proof:       fmt.Sprintf("Line %d: PasswordAuthentication %s", lineNum, parts[1]),
							Remediation: "Set 'PasswordAuthentication no' in sshd_config and ensure authorized_keys are configured.",
							Compliance:  []string{"CIS", "CIS-4.8"},
						})
					}
					if key == "protocol" && val == "1" {
						*findings = append(*findings, &audit.SCAFinding{
							Timestamp:   now,
							RuleID:      "CIS-4.1",
							Title:       "SSH Protocol 1 Enabled",
							Description: "SSH Protocol 1 contains multiple vulnerability issues and must be disabled in favor of Protocol 2.",
							Severity:    "critical",
							FilePath:    path,
							Proof:       fmt.Sprintf("Line %d: Protocol %s", lineNum, parts[1]),
							Remediation: "Remove 'Protocol 1' or set 'Protocol 2' in sshd_config.",
							Compliance:  []string{"CIS", "CIS-4.1"},
						})
					}
				}
			}
		}

		// C. Check Linux Sysctl Configuration (CIS-4.1)
		if isSysctlConfig {
			cleanLine := strings.TrimSpace(line)
			if cleanLine != "" && !strings.HasPrefix(cleanLine, "#") {
				if strings.Contains(cleanLine, "=") {
					parts := strings.SplitN(cleanLine, "=", 2)
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])

					if key == "net.ipv4.ip_forward" && val == "1" {
						*findings = append(*findings, &audit.SCAFinding{
							Timestamp:   now,
							RuleID:      "CIS-4.1",
							Title:       "IP Forwarding Enabled",
							Description: "IP forwarding is enabled. Unless this system acts as a router, forwarding should be disabled to prevent routing malicious packets between subnets.",
							Severity:    "medium",
							FilePath:    path,
							Proof:       fmt.Sprintf("Line %d: net.ipv4.ip_forward = %s", lineNum, val),
							Remediation: "Set 'net.ipv4.ip_forward = 0' in sysctl.conf and run 'sysctl -p'.",
							Compliance:  []string{"CIS", "CIS-4.1"},
						})
					}
					if key == "net.ipv4.conf.all.accept_redirects" && val == "1" {
						*findings = append(*findings, &audit.SCAFinding{
							Timestamp:   now,
							RuleID:      "CIS-4.1",
							Title:       "ICMP Redirects Accepted",
							Description: "The system accepts ICMP redirect messages, which can make it vulnerable to Man-in-the-Middle (MitM) attacks or routing table alterations.",
							Severity:    "low",
							FilePath:    path,
							Proof:       fmt.Sprintf("Line %d: net.ipv4.conf.all.accept_redirects = %s", lineNum, val),
							Remediation: "Set 'net.ipv4.conf.all.accept_redirects = 0' in sysctl.conf.",
							Compliance:  []string{"CIS", "CIS-4.1"},
						})
					}
				}
			}
		}
	}
}
