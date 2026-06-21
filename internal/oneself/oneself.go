// Package oneself implements self-update (from GitHub releases) and uninstall
// functionality, mirroring the Rust oneself module.
package oneself

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	repoOwner = "0x676e67"
	repoName  = "outway"
	binName   = "outway"
)

// currentVersion is the build-time version string. It can be overridden via
// -ldflags "-X github.com/xiaozhou26/outway/internal/oneself.currentVersion=x.y.z".
var currentVersion = "0.0.0"

// githubRelease represents the relevant fields of a GitHub release API response.
type githubRelease struct {
	TagName string       `json:"tag_name"`
	Name    string       `json:"name"`
	Body    string       `json:"body"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents a release asset.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Update downloads and installs the latest version from GitHub releases.
func Update() error {
	fmt.Printf("Checking for updates...\n")

	release, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	if latestVersion == currentVersion {
		fmt.Printf("%s is up-to-date\n", binName)
		return nil
	}

	target := currentTarget()
	asset, err := findAsset(release, target)
	if err != nil {
		return err
	}

	fmt.Printf("Downloading %s...\n", asset.Name)

	tmpPath, err := downloadAsset(asset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download asset: %w", err)
	}
	defer os.Remove(tmpPath)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	binaryData, err := extractBinary(tmpPath, asset.Name)
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	if err := replaceExecutable(exePath, binaryData); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}

	if release.Body != "" && strings.TrimSpace(release.Body) != "" {
		fmt.Printf("%s upgraded to %s:\n\n", binName, latestVersion)
		fmt.Println(release.Body)
	} else {
		fmt.Printf("%s upgraded to %s\n", binName, latestVersion)
	}

	return nil
}

// Uninstall removes the current executable.
func Uninstall() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	fmt.Printf("Uninstalling %s\n", exePath)

	if err := os.Remove(exePath); err != nil {
		return fmt.Errorf("remove executable: %w", err)
	}

	fmt.Println("Uninstallation complete.")
	return nil
}

// fetchLatestRelease fetches the latest release from the GitHub API.
func fetchLatestRelease() (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API returned %d: %s", resp.StatusCode, string(body))
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// currentTarget returns the Rust-style target triple for the current platform.
func currentTarget() string {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		case "386":
			return "i686-unknown-linux-gnu"
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-apple-darwin"
		case "arm64":
			return "aarch64-apple-darwin"
		}
	case "windows":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-pc-windows-msvc"
		case "arm64":
			return "aarch64-pc-windows-msvc"
		}
	case "freebsd":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-unknown-freebsd"
		}
	}
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// findAsset finds the release asset matching the current target.
func findAsset(release *githubRelease, target string) (*githubAsset, error) {
	for i, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, strings.ToLower(target)) {
			return &release.Assets[i], nil
		}
	}
	// Fallback: try a looser match on OS + arch keywords.
	osKey := runtime.GOOS
	archKey := runtime.GOARCH
	for i, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, osKey) && strings.Contains(name, archKey) {
			return &release.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("no release asset found for target %s", target)
}

// downloadAsset downloads the asset at the given URL to a temporary file.
func downloadAsset(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "outway-update-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

// extractBinary extracts the outway binary from the downloaded file. If the
// file is a tar.gz, it extracts the binary; otherwise it treats the file as
// a raw binary.
func extractBinary(path, assetName string) ([]byte, error) {
	name := strings.ToLower(assetName)

	if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
		return extractFromTarGz(path)
	}
	if strings.HasSuffix(name, ".gz") {
		return readGzip(path)
	}
	// Treat as raw binary.
	return os.ReadFile(path)
}

// extractFromTarGz extracts the outway binary from a tar.gz archive.
func extractFromTarGz(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		base := filepath.Base(hdr.Name)
		if base == binName || base == binName+".exe" {
			return io.ReadAll(tr)
		}
	}
	return nil, errors.New("binary not found in archive")
}

// readGzip reads a gzipped file.
func readGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

// replaceExecutable replaces the current executable with the new binary data.
func replaceExecutable(exePath string, data []byte) error {
	// Write to a temporary file in the same directory, then rename.
	dir := filepath.Dir(exePath)
	tmp, err := os.CreateTemp(dir, ".outway-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// On Windows, we can't rename over a running executable, so remove first.
	if runtime.GOOS == "windows" {
		_ = os.Remove(exePath)
	}

	return os.Rename(tmpPath, exePath)
}
