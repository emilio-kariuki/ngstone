package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withXDG(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", dir)
}

func TestPathHonorsXDGConfigHome(t *testing.T) {
	tmp := t.TempDir()
	withXDG(t, tmp)

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	want := filepath.Join(tmp, "ngstone", "config.json")
	if got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestLoadMissingFileReturnsZeroValueNoError(t *testing.T) {
	tmp := t.TempDir()
	withXDG(t, tmp)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() on missing file returned error: %v", err)
	}
	if cfg != (Config{}) {
		t.Fatalf("Load() on missing file = %+v, want zero value", cfg)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	withXDG(t, tmp)

	want := Config{Token: "z_eP-5W8EDORawyXe9YV9ZwMB", Server: "ngstone.site:4443"}
	if err := Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("Load() = %+v, want %+v", got, want)
	}
}

func TestSaveFileAndDirModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions do not apply on windows")
	}
	tmp := t.TempDir()
	withXDG(t, tmp)

	if err := Save(Config{Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("config dir mode = %o, want 0700", perm)
	}
}

func TestSaveTightensLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions do not apply on windows")
	}
	tmp := t.TempDir()
	withXDG(t, tmp)

	if err := Save(Config{Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := Save(Config{Token: "tok2"}); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode after re-save = %o, want 0600", perm)
	}
}

func TestFailedWriteLeavesPreviousTokenIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-based write failures behave differently on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission checks, cannot force a write failure this way")
	}
	tmp := t.TempDir()
	withXDG(t, tmp)

	original := Config{Token: "original-secret-token", Server: "ngstone.site:4443"}
	if err := Save(original); err != nil {
		t.Fatalf("initial Save: %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir read-only: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	err = Save(Config{Token: "new-token-that-should-not-land", Server: "evil.example.com"})
	if err == nil {
		t.Fatalf("expected Save to fail while the config dir is not writable")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore dir perms: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load after failed save: %v", err)
	}
	if got != original {
		t.Fatalf("config after failed write = %+v, want unchanged original %+v", got, original)
	}
}

func TestRedactedNeverExposesFullToken(t *testing.T) {
	cfg := Config{Token: "z_eP-5W8EDORawyXe9YV9ZwMB-fa1ITKh6e5Cctkwyc", Server: "ngstone.site:4443"}
	red := cfg.Redacted()

	if red.Token == cfg.Token {
		t.Fatalf("Redacted() returned the token unchanged")
	}
	if red.Server != cfg.Server {
		t.Fatalf("Redacted() changed Server: got %q, want %q", red.Server, cfg.Server)
	}
	if len(red.Token) >= len(cfg.Token) {
		t.Fatalf("redacted token %q is not shorter than the original", red.Token)
	}
}

func TestRedactedEmptyToken(t *testing.T) {
	cfg := Config{Server: "ngstone.site:4443"}
	red := cfg.Redacted()
	if red.Token != "" {
		t.Fatalf("Redacted() of empty token = %q, want empty", red.Token)
	}
}
