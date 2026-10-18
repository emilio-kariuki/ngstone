package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngstone/internal/config"
)

func TestServicesUseDistinctPrivateCredentials(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			home, _, _ := setupServiceEnv(t, goos, false)
			t.Setenv("NGSTONE_TOKEN", "ambient-token")
			for _, name := range []string{"web", "api", "pool"} {
				if err := os.WriteFile(filepath.Join(home, name+".token"), []byte(name+"-private-token\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, format := range []string{"json", "yml"} {
				t.Run(format, func(t *testing.T) {
					content := `{"tunnels":{"web":{"target":"3000","subdomain":"web","credential_file":"web.token","multi_connector":true,"connector_token_file":"pool.token"},"api":{"target":"4000","subdomain":"api","credential_file":"api.token"}}}`
					if format == "yml" {
						content = "tunnels:\n  web:\n    port: 3000\n    subdomain: web\n    credential_file: web.token\n    multi_connector: true\n    connector_token_file: pool.token\n  api:\n    port: 4000\n    subdomain: api\n    credential_file: api.token\n"
					}
					path := filepath.Join(home, "ngstone."+format)
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
					spec, err := buildServiceSpec(path, nil)
					if err != nil {
						t.Fatal(err)
					}
					_, definition, err := serviceDefinition(spec)
					if err != nil {
						t.Fatal(err)
					}
					for _, secret := range []string{"web-private-token", "api-private-token", "pool-private-token", "ambient-token"} {
						if strings.Contains(definition, secret) {
							t.Fatal("service definition exposes a token")
						}
					}
					selected, err := loadConfiguredTunnels(path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if len(selected) != 2 {
						t.Fatalf("tunnels = %d", len(selected))
					}
					for _, named := range selected {
						acfg, _, err := buildProjectAgent(named.Name, named.Tunnel, home, config.Config{})
						if err != nil {
							t.Fatal(err)
						}
						if acfg.Token != named.Name+"-private-token" {
							t.Fatal("tunnel did not use its scoped credential file")
						}
						if named.Name == "web" && acfg.ConnectorToken != "pool-private-token" {
							t.Fatal("pool file was not loaded")
						}
					}
				})
			}
		})
	}
}

func TestServicesRejectEphemeralCredentials(t *testing.T) {
	home, _, _ := setupServiceEnv(t, "linux", false)
	t.Setenv("NGSTONE_WEB_TOKEN", "ephemeral-token")
	path := filepath.Join(home, "ngstone.json")
	if err := os.WriteFile(path, []byte(`{"tunnels":{"web":{"target":"3000","credential_env":"NGSTONE_WEB_TOKEN"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildServiceSpec(path, nil); err == nil || !strings.Contains(err.Error(), "credential_file") {
		t.Fatalf("environment-only service: %v", err)
	}
}
