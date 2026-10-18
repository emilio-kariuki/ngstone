package main

import (
	"errors"
	"flag"
	"fmt"
	"html"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"ngstone/internal/config"
)

const (
	systemdUnitName = "ngstone.service"
	launchdLabel    = "site.ngstone.agent"
)

// Hooks for tests: the platform, how commands run, and where files go.
var (
	serviceGOOS   = runtime.GOOS
	runServiceCmd = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	serviceHomeDir = os.UserHomeDir
)

// serviceSpec is what the background service runs.
type serviceSpec struct {
	exe  string
	args []string
	env  map[string]string // passed through so the service finds the same config
}

func cmdService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone service install|uninstall|status [--config FILE] [name ...]")
		return 2
	}
	switch args[0] {
	case "install":
		return serviceInstall(args[1:])
	case "uninstall":
		return serviceUninstall()
	case "status":
		return serviceStatus()
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown service command %q; use install, uninstall or status\n", args[0])
		return 2
	}
}

func serviceInstall(args []string) int {
	flags := flag.NewFlagSet("service install", flag.ContinueOnError)
	cfgPath := flags.String("config", "", "tunnels file to run (default ./"+config.TunnelsFileName+", then tunnels.yml in the config directory)")
	printOnly := flags.Bool("print", false, "print the service definition instead of installing it")
	names, err := parsePermissive(flags, args)
	if err != nil {
		return 2
	}

	spec, err := buildServiceSpec(*cfgPath, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}

	path, content, err := serviceDefinition(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	if *printOnly {
		fmt.Printf("# %s\n%s", path, content)
		return 0
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: writing %s: %v\n", path, err)
		return 1
	}
	if err := startService(path); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: wrote %s but could not start it: %v\n", path, err)
		return 1
	}

	fmt.Printf("installed %s\n", path)
	switch serviceGOOS {
	case "linux":
		fmt.Println("logs:    journalctl --user -u ngstone -f")
		fmt.Println("to keep it running after you log out and start it at boot:  sudo loginctl enable-linger $USER")
	case "darwin":
		fmt.Printf("logs:    %s\n", launchdLogPath(filepath.Dir(filepath.Dir(filepath.Dir(path)))))
	}
	return 0
}

// buildServiceSpec checks everything the service will need up front, so a
// broken setup fails here instead of in a restart loop in the background.
func buildServiceSpec(cfgPath string, names []string) (serviceSpec, error) {
	path, err := config.TunnelsPath(cfgPath)
	if err != nil {
		return serviceSpec{}, err
	}
	tunnels, err := loadConfiguredTunnels(path, names)
	if err != nil {
		return serviceSpec{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return serviceSpec{}, err
	}

	saved, err := config.Load()
	if err != nil {
		return serviceSpec{}, fmt.Errorf("loading config: %w", err)
	}
	for _, named := range tunnels {
		tunnel := named.Tunnel
		if tunnel.MultiConnector && tunnel.ConnectorTokenFile == "" {
			return serviceSpec{}, fmt.Errorf("tunnel %s: background connector pools require connector_token_file", named.Name)
		}
		if tunnel.CredentialEnv != "" {
			return serviceSpec{}, fmt.Errorf("tunnel %s: background credentials must use credential_file so they survive logout and restart", named.Name)
		}
		if tunnel.CredentialFile == "" {
			if saved.Token == "" {
				return serviceSpec{}, errors.New("the service needs credential_file for each tunnel or the token saved by 'ngstone auth'")
			}
			tunnel.Token = saved.Token
		}
		if _, _, err := buildProjectAgent(named.Name, tunnel, filepath.Dir(abs), saved); err != nil {
			return serviceSpec{}, fmt.Errorf("tunnel %s: %w", named.Name, err)
		}
	}

	exe, err := stableExecutable()
	if err != nil {
		return serviceSpec{}, err
	}

	spec := serviceSpec{
		exe:  exe,
		args: append([]string{"start", "--no-tui", "--config", abs}, names...),
		env:  map[string]string{},
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		spec.env["XDG_CONFIG_HOME"] = v
	}
	return spec, nil
}

// stableExecutable prefers the ngstone found on PATH when it is this same
// binary: package managers expose a stable symlink there, while the
// resolved path often contains a version that an upgrade removes.
func stableExecutable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("finding the ngstone binary: %w", err)
	}
	if onPath, err := exec.LookPath("ngstone"); err == nil {
		if abs, err := filepath.Abs(onPath); err == nil {
			a, errA := os.Stat(abs)
			b, errB := os.Stat(self)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return abs, nil
			}
		}
	}
	return self, nil
}

// serviceDefinition renders the unit or plist and where it belongs.
func serviceDefinition(spec serviceSpec) (path, content string, err error) {
	home, err := serviceHomeDir()
	if err != nil {
		return "", "", err
	}
	switch serviceGOOS {
	case "linux":
		return systemdUnitPath(home), renderSystemdUnit(spec), nil
	case "darwin":
		return launchdPlistPath(home), renderLaunchdPlist(spec, launchdLogPath(home)), nil
	default:
		return "", "", fmt.Errorf("ngstone service supports Linux (systemd) and macOS (launchd), not %s", serviceGOOS)
	}
}

func systemdUnitPath(home string) string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user", systemdUnitName)
}

func launchdPlistPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

func launchdLogPath(home string) string {
	return filepath.Join(home, "Library", "Logs", "ngstone.log")
}

// systemdQuote quotes one ExecStart word: systemd splits on whitespace and
// honours double quotes with C-style escapes, and expands % specifiers.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\%$") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

func renderSystemdUnit(spec serviceSpec) string {
	words := []string{systemdQuote(spec.exe)}
	for _, a := range spec.args {
		words = append(words, systemdQuote(a))
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=ngstone tunnels\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("ExecStart=" + strings.Join(words, " ") + "\n")
	for _, k := range sortedKeys(spec.env) {
		b.WriteString("Environment=" + systemdQuote(k+"="+spec.env[k]) + "\n")
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=10s\n")
	b.WriteString("TimeoutStopSec=30s\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String()
}

func renderLaunchdPlist(spec serviceSpec, logPath string) string {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	b.WriteString("\t\t<string>" + esc(spec.exe) + "</string>\n")
	for _, a := range spec.args {
		b.WriteString("\t\t<string>" + esc(a) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	if len(spec.env) > 0 {
		b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, k := range sortedKeys(spec.env) {
			b.WriteString("\t\t<key>" + esc(k) + "</key>\n\t\t<string>" + esc(spec.env[k]) + "</string>\n")
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString(`	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>` + esc(logPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + esc(logPath) + `</string>
</dict>
</plist>
`)
	return b.String()
}

func startService(path string) error {
	switch serviceGOOS {
	case "linux":
		if err := runServiceCmd("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := runServiceCmd("systemctl", "--user", "enable", systemdUnitName); err != nil {
			return err
		}
		// restart, not start: a reinstall must pick up the new definition.
		return runServiceCmd("systemctl", "--user", "restart", systemdUnitName)
	case "darwin":
		domain := "gui/" + strconv.Itoa(os.Getuid())
		_ = runServiceCmd("launchctl", "bootout", domain+"/"+launchdLabel) // not loaded yet is fine
		return runServiceCmd("launchctl", "bootstrap", domain, path)
	}
	return fmt.Errorf("unsupported platform %s", serviceGOOS)
}

func serviceUninstall() int {
	home, err := serviceHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	var path string
	switch serviceGOOS {
	case "linux":
		path = systemdUnitPath(home)
		_ = runServiceCmd("systemctl", "--user", "disable", "--now", systemdUnitName)
	case "darwin":
		path = launchdPlistPath(home)
		_ = runServiceCmd("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+launchdLabel)
	default:
		fmt.Fprintf(os.Stderr, "ngstone: service is not supported on %s\n", serviceGOOS)
		return 1
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "ngstone: removing %s: %v\n", path, err)
		return 1
	}
	if serviceGOOS == "linux" {
		_ = runServiceCmd("systemctl", "--user", "daemon-reload")
	}
	fmt.Printf("removed %s\n", path)
	return 0
}

func serviceStatus() int {
	var err error
	switch serviceGOOS {
	case "linux":
		err = runServiceCmd("systemctl", "--user", "status", "--no-pager", systemdUnitName)
	case "darwin":
		err = runServiceCmd("launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+launchdLabel)
	default:
		fmt.Fprintf(os.Stderr, "ngstone: service is not supported on %s\n", serviceGOOS)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
