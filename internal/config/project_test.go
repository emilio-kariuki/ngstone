package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeProject(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ngstone.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write project: %v", err)
	}
	return path
}

func TestLoadProjectNormalizesAndSortsTunnels(t *testing.T) {
	path := writeProject(t, `{
  "tunnels": {
    "z-api": {"target": "3001", "kind": "HTTP", "ttl": "90m"},
    "a-web": {"target": "3000", "subdomain": "demo"}
  }
}`)
	project, err := LoadProject(path)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if project.Tunnels["z-api"].Kind != "http" {
		t.Fatalf("kind = %q, want http", project.Tunnels["z-api"].Kind)
	}
	if got := project.Tunnels["z-api"].TTL; got != "90m" {
		t.Fatalf("ttl = %q, want 90m", got)
	}
	ordered := project.SortedTunnels()
	if len(ordered) != 2 || ordered[0].Name != "a-web" || ordered[1].Name != "z-api" {
		t.Fatalf("sorted tunnels = %+v", ordered)
	}
}

func TestLoadProjectRejectsUnknownFields(t *testing.T) {
	path := writeProject(t, `{"tunnels":{"web":{"target":"3000","token":"secret"}}}`)
	_, err := LoadProject(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadProject error = %v, want unknown field error", err)
	}
}

func TestLoadProjectRejectsInvalidTTLAndKind(t *testing.T) {
	cases := []string{
		`{"tunnels":{"web":{"target":"3000","ttl":"0s"}}}`,
		`{"tunnels":{"web":{"target":"3000","kind":"udp"}}}`,
		`{"tunnels":{"web":{"target":"3000","host_header":"demo.local","kind":"tcp"}}}`,
		`{"tunnels":{"web":{"target":"3000","basic_auth_file":"credentials","kind":"tcp"}}}`,
		`{"tunnels":{"web":{"target":"3000","policy_file":"traffic-policy.json","kind":"tcp"}}}`,
		`{"tunnels":{"web":{"target":"3000","http2":true,"kind":"tcp"}}}`,
		`{"tunnels":{"web":{"target":"3000","multi_connector":true,"kind":"tcp"}}}`,
		`{"tunnels":{"web":{"target":"3000","multi_connector":true}}}`,
		`{"tunnels":{"web":{"target":"3000","remote_port":15432}}}`,
		`{"tunnels":{"web":{"target":"3000","credential_env":"not-valid"}}}`,
	}
	for _, data := range cases {
		_, err := LoadProject(writeProject(t, data))
		if err == nil {
			t.Fatalf("LoadProject(%s) succeeded, want validation error", data)
		}
	}
}

func TestProjectTunnelTTLDuration(t *testing.T) {
	tunnel := ProjectTunnel{TTL: "2h"}
	ttl, err := tunnel.TTLDuration()
	if err != nil {
		t.Fatalf("TTLDuration: %v", err)
	}
	if ttl != 2*time.Hour {
		t.Fatalf("ttl = %s, want 2h", ttl)
	}
	if _, err := (ProjectTunnel{TTL: "-1m"}).TTLDuration(); err == nil {
		t.Fatal("negative ttl accepted")
	}
}

func TestFindProject(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	if _, err := FindProject(""); err == nil {
		t.Fatal("FindProject without a file succeeded")
	}
	path := filepath.Join(dir, DefaultProjectFilename)
	if err := os.WriteFile(path, []byte(`{"tunnels":{"web":{"target":"3000"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FindProject("")
	if err != nil {
		t.Fatalf("FindProject: %v", err)
	}
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("resolve FindProject result: %v", err)
	}
	wantResolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve expected project path: %v", err)
	}
	if gotResolved != wantResolved {
		t.Fatalf("FindProject = %q, want %q", got, path)
	}
}
