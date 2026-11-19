package oneself

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFindAssetMatchesRustTargetTriple(t *testing.T) {
	release := &githubRelease{Assets: []githubAsset{
		{Name: "outway-aarch64-unknown-linux-gnu.tar.gz"},
		{Name: "outway-x86_64-unknown-linux-gnu.tar.gz"},
		{Name: "outway-x86_64-pc-windows-msvc.zip"},
	}}
	asset, err := findAsset(release, "x86_64-unknown-linux-gnu")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != "outway-x86_64-unknown-linux-gnu.tar.gz" {
		t.Fatalf("asset = %q", asset.Name)
	}
}

func TestFindAssetCaseInsensitive(t *testing.T) {
	release := &githubRelease{Assets: []githubAsset{
		{Name: "OUTWAY-X86_64-UNKNOWN-LINUX-GNU.TAR.GZ"},
	}}
	asset, err := findAsset(release, "x86_64-unknown-linux-gnu")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != "OUTWAY-X86_64-UNKNOWN-LINUX-GNU.TAR.GZ" {
		t.Fatalf("asset = %q", asset.Name)
	}
}

// TestFindAssetGoStyleFallback pins the fallback that matches Go-style
// os/arch keywords when no Rust-style triple asset exists. The asset names are
// derived from the test host's GOOS/GOARCH so the case is portable.
func TestFindAssetGoStyleFallback(t *testing.T) {
	goStyle := "outway-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
	release := &githubRelease{Assets: []githubAsset{
		{Name: "outway-some-other-target.tar.gz"},
		{Name: goStyle},
	}}
	asset, err := findAsset(release, "x86_64-unknown-linux-gnu")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != goStyle {
		t.Fatalf("asset = %q, want %q", asset.Name, goStyle)
	}
}

func TestFindAssetNoMatch(t *testing.T) {
	release := &githubRelease{Assets: []githubAsset{
		{Name: "outway-aarch64-unknown-linux-gnu.tar.gz"},
	}}
	if _, err := findAsset(release, "mips64-unknown-linux-musl"); err == nil {
		t.Fatal("expected no-asset error")
	}
}

func TestRepoPointsAtThisProject(t *testing.T) {
	if repoOwner != "xiaozhou26" || repoName != "outway" {
		t.Fatalf("self update targets %s/%s, want xiaozhou26/outway", repoOwner, repoName)
	}
}

// TestFindAssetPrefersReleaseWorkflowName pins the names release.yml
// publishes, and checks an exact match beats a looser one listed first.
func TestFindAssetPrefersReleaseWorkflowName(t *testing.T) {
	want := goAssetName(runtime.GOOS, runtime.GOARCH)
	release := &githubRelease{Assets: []githubAsset{
		{Name: want + ".sha256"},
		{Name: want},
	}}
	asset, err := findAsset(release, currentTarget())
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != want {
		t.Fatalf("asset = %q, want %q", asset.Name, want)
	}
}

func TestGoAssetNameMatchesReleaseWorkflow(t *testing.T) {
	if got := goAssetName("linux", "amd64"); got != "outway-linux-amd64.tar.gz" {
		t.Fatalf("linux asset = %q", got)
	}
	if got := goAssetName("windows", "arm64"); got != "outway-windows-arm64.zip" {
		t.Fatalf("windows asset = %q", got)
	}
}

func TestExtractBinaryFromReleaseArchives(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("#!binary")

	tgz := filepath.Join(dir, "outway-linux-amd64.tar.gz")
	writeTarGz(t, tgz, "outway-linux-amd64", payload)
	got, err := extractBinary(tgz, filepath.Base(tgz))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("tar.gz: %q, %v", got, err)
	}

	zipPath := filepath.Join(dir, "outway-windows-amd64.zip")
	writeZip(t, zipPath, "outway-windows-amd64.exe", payload)
	got, err = extractBinary(zipPath, filepath.Base(zipPath))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("zip: %q, %v", got, err)
	}
}

func TestIsBinaryName(t *testing.T) {
	for name, want := range map[string]bool{
		"outway":                   true,
		"outway.exe":               true,
		"dist/outway-linux-amd64":  true,
		"outway-windows-arm64.exe": true,
		"README.md":                false,
		"outwayx":                  false,
	} {
		if got := isBinaryName(name); got != want {
			t.Errorf("isBinaryName(%q) = %v, want %v", name, got, want)
		}
	}
}

func writeTarGz(t *testing.T, path, member string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path, member string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	w, err := zw.Create(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
