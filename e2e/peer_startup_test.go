package e2e

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEdgeRefusesPeerAddrWithoutPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess startup test in -short mode")
	}
	edgeBin := filepath.Join(t.TempDir(), "ngstoned")
	buildBinary(t, edgeBin, "ngstone/cmd/ngstoned")

	cases := []struct {
		name  string
		extra func(peerAddr string) (args, env []string)
		want  string
	}{
		{
			name: "peer address with the default SQLite configuration",
			extra: func(peerAddr string) ([]string, []string) {
				return []string{"-database-url", filepath.Join(t.TempDir(), "control.db")}, []string{"NGSTONE_PEER_ADDR=" + peerAddr}
			},
			want: "PostgreSQL",
		},
		{
			name: "peer listen address without a peer address",
			extra: func(peerAddr string) ([]string, []string) {
				return []string{"-token-sha256", sha256Hex("e2e-token"), "-peer-listen", peerAddr}, []string{}
			},
			want: "-peer-listen (or $NGSTONE_PEER_LISTEN) requires -peer-addr",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			controlAddr, publicAddr, peerAddr := freeAddr(t), freeAddr(t), freeAddr(t)
			extraArgs, env := tc.extra(peerAddr)
			args := append([]string{
				"-public", publicAddr,
				"-control", controlAddr,
				"-domain", "tun.example.com",
				"-public-scheme", "http",
				"-insecure",
				"-ops", "",
			}, extraArgs...)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, edgeBin, args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("ngstoned was still running after 5s; output:\n%s", out)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
				t.Fatalf("ngstoned exit = %v, want a non-zero exit; output:\n%s", err, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output does not mention %q:\n%s", tc.want, out)
			}
			for _, addr := range []string{controlAddr, publicAddr, peerAddr} {
				if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
					conn.Close()
					t.Fatalf("something listens on %s after the refusal", addr)
				}
			}
		})
	}
}
