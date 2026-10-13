package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngstone/internal/config"
)

// setupServiceEnv points the config directory and home at a temp dir, saves
// a token, writes a tunnels file, and records service manager commands.
func setupServiceEnv(t *testing.T, goos string, saveToken bool) (home, tunnelsPath string, calls *[]string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	if saveToken {
		if err := config.Save(config.Config{Token: "tok", Server: "example.com:4443"}); err != nil {
			t.Fatal(err)
		}
	}
	tunnelsPath = filepath.Join(home, "my tunnels", "ngstone.yml")
	os.MkdirAll(filepath.Dir(tunnelsPath), 0o755)
	os.WriteFile(tunnelsPath, []byte("tunnels:\n  web:\n    port: 3000\n"), 0o600)

	var recorded []string
	prevGOOS, prevRun, prevHome := serviceGOOS, runServiceCmd, serviceHomeDir
	serviceGOOS = goos
	runServiceCmd = func(name string, args ...string) error {
		recorded = append(recorded, name+" "+strings.Join(args, " "))
		return nil
	}
	serviceHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { serviceGOOS, runServiceCmd, serviceHomeDir = prevGOOS, prevRun, prevHome })
	return home, tunnelsPath, &recorded
}

func TestServiceInstallLinuxWritesUnitAndStartsIt(t *testing.T) {
	home, tunnelsPath, calls := setupServiceEnv(t, "linux", true)

	if code := cmdService([]string{"install", "--config", tunnelsPath, "web"}); code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	unitPath := filepath.Join(home, "cfg", "systemd", "user", "ngstone.service")
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("unit not written: %v", err)
	}
	for _, want := range []string{
		"start --no-tui --config \"" + tunnelsPath + "\" web", // path with a space is quoted
		"Environment=" + systemdQuote("XDG_CONFIG_HOME="+filepath.Join(home, "cfg")),
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
	got := strings.Join(*calls, "\n")
	want := "systemctl --user daemon-reload\nsystemctl --user enable ngstone.service\nsystemctl --user restart ngstone.service"
	if got != want {
		t.Fatalf("commands:\n%s\nwant:\n%s", got, want)
	}

	*calls = nil
	if code := cmdService([]string{"uninstall"}); code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("unit still present after uninstall: %v", err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "systemctl --user disable --now ngstone.service") {
		t.Fatalf("uninstall did not stop the service: %v", *calls)
	}
}

func TestServiceInstallMacWritesPlistAndBootstrapsIt(t *testing.T) {
	home, tunnelsPath, calls := setupServiceEnv(t, "darwin", true)

	if code := cmdService([]string{"install", "--config", tunnelsPath}); code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "site.ngstone.agent.plist")
	plist, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	for _, want := range []string{"<string>site.ngstone.agent</string>", "<string>" + tunnelsPath + "</string>", "<string>--no-tui</string>", "Library/Logs/ngstone.log"} {
		if !strings.Contains(string(plist), want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "launchctl bootstrap gui/") || !strings.Contains(joined, plistPath) {
		t.Fatalf("plist not bootstrapped: %v", *calls)
	}
}

func TestServiceInstallRefusesWithoutSavedToken(t *testing.T) {
	_, tunnelsPath, calls := setupServiceEnv(t, "linux", false)
	if code := cmdService([]string{"install", "--config", tunnelsPath}); code == 0 {
		t.Fatal("install succeeded without a saved token")
	}
	if len(*calls) != 0 {
		t.Fatalf("service manager was called: %v", *calls)
	}
}

func TestServiceInstallRefusesUnknownTunnelAndMissingFile(t *testing.T) {
	_, tunnelsPath, _ := setupServiceEnv(t, "linux", true)
	if code := cmdService([]string{"install", "--config", tunnelsPath, "nope"}); code == 0 {
		t.Fatal("install accepted an unknown tunnel name")
	}
	if code := cmdService([]string{"install", "--config", tunnelsPath + ".missing"}); code == 0 {
		t.Fatal("install accepted a missing tunnels file")
	}
}

func TestServiceInstallRejectsUnsupportedPlatform(t *testing.T) {
	_, tunnelsPath, _ := setupServiceEnv(t, "windows", true)
	if code := cmdService([]string{"install", "--config", tunnelsPath}); code == 0 {
		t.Fatal("install claimed to work on windows")
	}
}

func TestSystemdQuoteAndPlistEscaping(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/ngstone": "/usr/local/bin/ngstone",
		"/home/a b/x":            `"/home/a b/x"`,
		`50%"done"`:              `"50%%\"done\""`,
		"$HOME":                  `"$$HOME"`,
	}
	for in, want := range cases {
		if got := systemdQuote(in); got != want {
			t.Fatalf("systemdQuote(%q) = %s, want %s", in, got, want)
		}
	}
	plist := renderLaunchdPlist(serviceSpec{exe: "/bin/ngstone", args: []string{"--config", "/a&b/<c>.yml"}}, "/log")
	if !strings.Contains(plist, "/a&amp;b/&lt;c&gt;.yml") {
		t.Fatalf("plist did not escape XML:\n%s", plist)
	}
}
