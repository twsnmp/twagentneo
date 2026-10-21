package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// GitHubRelease represents the structure returned by GitHub Releases API
type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	HTMLURL     string        `json:"html_url"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a binary asset attached to a release
type GitHubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// UpdateInfo holds details about available updates
type UpdateInfo struct {
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	HasUpdate      bool      `json:"has_update"`
	ReleaseTitle   string    `json:"release_title"`
	ReleaseBody    string    `json:"release_body"`
	ReleaseURL     string    `json:"release_url"`
	PublishedAt    time.Time `json:"published_at"`
	IsContainer    bool      `json:"is_container"`
	IsHomebrew     bool      `json:"is_homebrew"`
	IsDebug        bool      `json:"is_debug"`
	Environment    string    `json:"environment"`
	CanSelfUpdate  bool      `json:"can_self_update"`
	UpdateGuide    string    `json:"update_guide"`
	AssetName      string    `json:"asset_name"`
	AssetURL       string    `json:"asset_url"`
	AssetSize      int64     `json:"asset_size"`
}

// UpdateStatus represents the live status of an in-progress self-update
type UpdateStatus struct {
	State    string `json:"state"` // "idle", "checking", "downloading", "extracting", "restarting", "completed", "error"
	Progress int    `json:"progress"`
	Message  string `json:"message"`
	Error    string `json:"error,omitempty"`
}

// Config holds configuration options for the Updater
type Config struct {
	CurrentVersion string
	Commit         string
	Debug          bool
	RepoOwner      string
	RepoName       string
	OnShutdown     func()
}

// Updater manages checking for updates, downloading releases, and binary replacement
type Updater struct {
	mu             sync.RWMutex
	currentVersion string
	commit         string
	debug          bool
	repoOwner      string
	repoName       string
	onShutdown     func()
	status         UpdateStatus
	cachedInfo     *UpdateInfo
	cachedETag     string
	cacheTime      time.Time
	cacheTTL       time.Duration
	httpClient     *http.Client
}

// New creates and initializes an Updater instance
func New(cfg Config) *Updater {
	owner := cfg.RepoOwner
	if owner == "" {
		owner = "twsnmp"
	}
	repo := cfg.RepoName
	if repo == "" {
		repo = "twagentneo"
	}

	return &Updater{
		currentVersion: cfg.CurrentVersion,
		commit:         cfg.Commit,
		debug:          cfg.Debug,
		repoOwner:      owner,
		repoName:       repo,
		onShutdown:     cfg.OnShutdown,
		cacheTTL:       1 * time.Hour,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		status: UpdateStatus{
			State:   "idle",
			Message: "Ready",
		},
	}
}

// IsContainer returns true if the current binary is running inside a Docker or containerized environment
func IsContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	if os.Getenv("container") == "docker" || os.Getenv("container") == "podman" {
		return true
	}
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			content := string(data)
			if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") || strings.Contains(content, "containerd") {
				return true
			}
		}
	}
	return false
}

// GetStatus returns the current live update status
func (u *Updater) GetStatus() UpdateStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

func (u *Updater) setStatus(state string, progress int, msg string, errStr string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = UpdateStatus{
		State:    state,
		Progress: progress,
		Message:  msg,
		Error:    errStr,
	}
}

// CheckUpdate checks GitHub Releases API for the latest release
func (u *Updater) CheckUpdate(ctx context.Context, force bool) (*UpdateInfo, error) {
	u.mu.RLock()
	if !force && u.cachedInfo != nil && time.Since(u.cacheTime) < u.cacheTTL {
		info := *u.cachedInfo
		u.mu.RUnlock()
		return &info, nil
	}
	cachedETag := u.cachedETag
	cachedInfo := u.cachedInfo
	u.mu.RUnlock()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.repoOwner, u.repoName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create update check request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "twagentneo-updater/"+u.currentVersion)
	if cachedETag != "" && !force {
		req.Header.Set("If-None-Match", cachedETag)
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		if cachedInfo != nil {
			slog.Warn("GitHub API check failed; returning cached release info", "error", err)
			return cachedInfo, nil
		}
		return nil, fmt.Errorf("failed to contact GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && cachedInfo != nil {
		u.mu.Lock()
		u.cacheTime = time.Now()
		u.mu.Unlock()
		return cachedInfo, nil
	}

	if resp.StatusCode == http.StatusForbidden {
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining == "0" {
			resetUnix := resp.Header.Get("X-RateLimit-Reset")
			resetTime := "soon"
			if sec, pErr := strconv.ParseInt(resetUnix, 10, 64); pErr == nil {
				resetTime = time.Unix(sec, 0).Format("15:04:05")
			}
			if cachedInfo != nil {
				slog.Warn("GitHub API rate limit exceeded; fallback to cached release info", "reset", resetTime)
				return cachedInfo, nil
			}
			return nil, fmt.Errorf("GitHub API rate limit reached (resets at %s). Set GITHUB_TOKEN or check again later", resetTime)
		}
		return nil, fmt.Errorf("GitHub API returned status: %d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status: %d", resp.StatusCode)
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub release response: %w", err)
	}

	info := u.buildUpdateInfo(&rel)
	newETag := resp.Header.Get("ETag")

	u.mu.Lock()
	u.cachedInfo = info
	u.cachedETag = newETag
	u.cacheTime = time.Now()
	u.mu.Unlock()

	return info, nil
}

func (u *Updater) buildUpdateInfo(rel *GitHubRelease) *UpdateInfo {
	cur := u.currentVersion
	if cur != "" && !strings.HasPrefix(cur, "v") && cur != "dev" && cur != "unknown" {
		cur = "v" + cur
	}
	latest := rel.TagName
	if latest != "" && !strings.HasPrefix(latest, "v") {
		latest = "v" + latest
	}

	hasUpdate := false
	if cur == "dev" || cur == "unknown" || cur == "" {
		hasUpdate = false
	} else if semver.IsValid(latest) && semver.IsValid(cur) {
		hasUpdate = semver.Compare(latest, cur) > 0
	} else if latest != cur {
		hasUpdate = true
	}

	env := DetectEnvironment(u.currentVersion, u.commit, u.debug)

	var matchedAsset *GitHubAsset
	osName := runtime.GOOS
	archName := runtime.GOARCH

	for i := range rel.Assets {
		name := strings.ToLower(rel.Assets[i].Name)
		if strings.Contains(name, osName) && strings.Contains(name, archName) {
			matchedAsset = &rel.Assets[i]
			break
		}
	}

	info := &UpdateInfo{
		CurrentVersion: cur,
		LatestVersion:  latest,
		HasUpdate:      hasUpdate,
		ReleaseTitle:   rel.Name,
		ReleaseBody:    rel.Body,
		ReleaseURL:     rel.HTMLURL,
		PublishedAt:    rel.PublishedAt,
		IsContainer:    env.IsContainer,
		IsHomebrew:     env.IsHomebrew,
		IsDebug:        env.IsDebug,
		Environment:    string(env.Type),
		CanSelfUpdate:  env.CanSelfUpdate,
		UpdateGuide:    env.UpdateGuide,
	}

	if matchedAsset != nil {
		info.AssetName = matchedAsset.Name
		info.AssetURL = matchedAsset.BrowserDownloadURL
		info.AssetSize = matchedAsset.Size
	}

	return info
}

// RunUpdateDirect executes the update pipeline synchronously
func (u *Updater) RunUpdateDirect(ctx context.Context, specificTag string) error {
	env := DetectEnvironment(u.currentVersion, u.commit, u.debug)
	if env.IsDebug {
		return errors.New("cannot perform self-update in debug mode; self-update is disabled")
	}
	if env.IsHomebrew {
		return errors.New("twagentneo is installed via Homebrew; please run 'brew update && brew upgrade twagentneo' to update")
	}
	if env.IsContainer {
		return errors.New("cannot perform in-place self-update within a container; please pull the latest container image instead")
	}
	if !env.CanSelfUpdate {
		return errors.New("self-update is not supported in this environment: " + env.UpdateGuide)
	}

	return u.runUpdatePipeline(ctx, specificTag)
}

func (u *Updater) runUpdatePipeline(ctx context.Context, specificTag string) error {
	u.setStatus("checking", 10, "Fetching release information...", "")

	var rel *GitHubRelease
	var err error
	if specificTag != "" {
		rel, err = u.fetchReleaseByTag(ctx, specificTag)
	} else {
		rel, err = u.fetchLatestRelease(ctx)
	}
	if err != nil {
		return fmt.Errorf("fetch release error: %w", err)
	}

	info := u.buildUpdateInfo(rel)
	if info.AssetURL == "" {
		return fmt.Errorf("no compatible release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	u.setStatus("downloading", 20, fmt.Sprintf("Downloading %s...", info.AssetName), "")
	tmpDir, err := os.MkdirTemp("", "twagentneo-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.AssetName)
	if err := u.downloadFile(ctx, info.AssetURL, archivePath, func(percent int) {
		u.setStatus("downloading", 20+int(float64(percent)*0.5), fmt.Sprintf("Downloading... %d%%", percent), "")
	}); err != nil {
		return fmt.Errorf("download error: %w", err)
	}

	u.setStatus("extracting", 75, "Extracting binary...", "")
	extractedBin, err := extractExecutable(archivePath, tmpDir)
	if err != nil {
		return fmt.Errorf("extraction error: %w", err)
	}

	if err := os.Chmod(extractedBin, 0755); err != nil {
		return fmt.Errorf("failed to chmod binary: %w", err)
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate current executable: %w", err)
	}
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("failed to resolve symlink for executable: %w", err)
	}

	u.setStatus("extracting", 85, "Backing up current binary...", "")
	bakPath := currentExe + ".bak"

	u.setStatus("extracting", 90, "Installing new executable...", "")
	if err := swapBinary(extractedBin, currentExe, bakPath); err != nil {
		return fmt.Errorf("failed to swap executable: %w", err)
	}

	u.setStatus("completed", 100, fmt.Sprintf("Updated to %s successfully!", info.LatestVersion), "")
	return nil
}

func (u *Updater) fetchLatestRelease(ctx context.Context) (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.repoOwner, u.repoName)
	return u.doReleaseRequest(ctx, url)
}

func (u *Updater) fetchReleaseByTag(ctx context.Context, tag string) (*GitHubRelease, error) {
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", u.repoOwner, u.repoName, tag)
	return u.doReleaseRequest(ctx, url)
}

func (u *Updater) doReleaseRequest(ctx context.Context, url string) (*GitHubRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "twagentneo-updater/"+u.currentVersion)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch release from %s: HTTP %d", url, resp.StatusCode)
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func (u *Updater) downloadFile(ctx context.Context, url, destPath string, onProgress func(percent int)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "twagentneo-updater/"+u.currentVersion)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download release: HTTP %d", resp.StatusCode)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	totalSize := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)
	lastReport := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := out.Write(buf[:n]); wErr != nil {
				return wErr
			}
			downloaded += int64(n)
			if totalSize > 0 && onProgress != nil && time.Since(lastReport) > 100*time.Millisecond {
				pct := int(float64(downloaded) / float64(totalSize) * 100)
				onProgress(pct)
				lastReport = time.Now()
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return rErr
		}
	}

	if onProgress != nil {
		onProgress(100)
	}
	return nil
}

func extractExecutable(archivePath, destDir string) (string, error) {
	lower := strings.ToLower(archivePath)
	targetName := "twagentneo"
	if runtime.GOOS == "windows" {
		targetName = "twagentneo.exe"
	}

	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return extractFromTarGz(archivePath, destDir, targetName)
	} else if strings.HasSuffix(lower, ".zip") {
		return extractFromZip(archivePath, destDir, targetName)
	}

	return "", fmt.Errorf("unsupported archive format: %s", filepath.Base(archivePath))
}

func extractFromTarGz(archivePath, destDir, targetName string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}

		name := filepath.Base(header.Name)
		if name == targetName && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			dest := filepath.Join(destDir, targetName)
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(out, tarReader); err != nil {
				out.Close()
				return "", err
			}
			out.Close()
			return dest, nil
		}
	}

	return "", fmt.Errorf("target executable '%s' not found inside archive", targetName)
}

func extractFromZip(archivePath, destDir, targetName string) (string, error) {
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return "", err
	}

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if strings.EqualFold(name, targetName) {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			dest := filepath.Join(destDir, targetName)
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				rc.Close()
				return "", err
			}
			if _, err := io.Copy(out, rc); err != nil {
				out.Close()
				rc.Close()
				return "", err
			}
			out.Close()
			rc.Close()
			return dest, nil
		}
	}

	return "", fmt.Errorf("target executable '%s' not found inside zip", targetName)
}

func swapBinary(newBinary, currentExe, bakPath string) error {
	if bakPath != "" {
		if _, err := os.Stat(currentExe); err == nil {
			_ = os.Remove(bakPath)
			if err := copyFile(currentExe, bakPath); err != nil {
				slog.Warn("Failed to copy executable to backup path", "error", err)
			}
		}
	}

	if runtime.GOOS == "windows" {
		_ = os.Remove(bakPath)
		if err := os.Rename(currentExe, bakPath); err != nil {
			return fmt.Errorf("failed to move current executable to backup: %w", err)
		}
		if err := copyFile(newBinary, currentExe); err != nil {
			_ = os.Rename(bakPath, currentExe)
			return fmt.Errorf("failed to install new executable: %w", err)
		}
		return nil
	}

	tempDest := filepath.Join(filepath.Dir(currentExe), ".twagentneo.update.tmp")
	_ = os.Remove(tempDest)

	if err := copyFile(newBinary, tempDest); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}
	if err := os.Chmod(tempDest, 0755); err != nil {
		_ = os.Remove(tempDest)
		return fmt.Errorf("failed to chmod staged binary: %w", err)
	}

	if err := os.Rename(tempDest, currentExe); err != nil {
		_ = os.Remove(tempDest)
		return fmt.Errorf("failed to replace binary atomically: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
