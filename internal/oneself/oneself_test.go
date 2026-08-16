package oneself

import (
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
