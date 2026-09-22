package sigma

import (
	"embed"
	"io/fs"
	"log"
	"path"
	"path/filepath"
	"strings"
)

// Embedded Sigma rules and configs.
// Rules are organized by OS: rules/linux/, rules/windows/, rules/darwin/.
// Sigma field-mapping configs live in rules/config/.
//
//go:embed all:rules all:config
var sigmaFS embed.FS

// ForEachSigmaConfig iterates over all embedded sigma config YAML files.
func ForEachSigmaConfig(callback func(name string, data []byte)) {
	entries, err := sigmaFS.ReadDir("config")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		p := path.Join("config", entry.Name())
		if d, err := sigmaFS.ReadFile(p); err == nil {
			callback(name, d)
		}
	}
}

// ForEachOSSigmaRules iterates over embedded Sigma rules for the specified OS.
// osLabel should be "linux", "windows", or "darwin".
func ForEachOSSigmaRules(osLabel string, callback func(data []byte, path, source string)) {
	rulesDir := path.Join("rules", osLabel)
	err := fs.WalkDir(sigmaFS, rulesDir, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := sigmaFS.ReadFile(filePath)
		if err != nil {
			log.Printf("[sigma] embedded read error %s: %v", filePath, err)
			return nil
		}
		source := "embed:" + filePath
		callback(data, filePath, source)
		return nil
	})
	if err != nil {
		log.Printf("[sigma] walk error for %s: %v", rulesDir, err)
	}
}

// GetEmbeddedOSLabels returns the list of OS labels that have embedded rules.
func GetEmbeddedOSLabels() []string {
	entries, err := sigmaFS.ReadDir("rules")
	if err != nil {
		return nil
	}
	var labels []string
	for _, entry := range entries {
		if entry.IsDir() {
			labels = append(labels, entry.Name())
		}
	}
	return labels
}
