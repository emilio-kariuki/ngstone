package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/status"
)

// publishStatus makes this process's tunnels visible to `ngstone ps` until
// the returned stop function is called or ctx ends. A failure only loses
// the listing, so it is logged and the tunnels run anyway.
func publishStatus(ctx context.Context, command string, cfgs []agent.Config, agents []*agent.Agent) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	started := time.Now()
	snapshot := func() status.Snapshot {
		snap := status.Snapshot{PID: os.Getpid(), Command: command, Started: started}
		for i, a := range agents {
			st := a.Status()
			kind := "http"
			if cfgs[i].Kind == "tcp" {
				kind = "tcp"
			}
			state := st.State
			if state == "" {
				state = agent.StateConnecting
			}
			snap.Tunnels = append(snap.Tunnels, status.Tunnel{
				Name:    cfgs[i].Name,
				Kind:    kind,
				State:   state,
				URL:     st.URL,
				Target:  cfgs[i].TargetURL,
				Err:     st.Err,
				Evicted: st.Evicted,
			})
		}
		return snap
	}
	if err := status.Serve(ctx, snapshot); err != nil {
		slog.Warn("ngstone: status socket unavailable; this process will not appear in ngstone ps", "err", err)
	}
	return cancel
}

func cmdPS(args []string) int {
	flags := flag.NewFlagSet("ps", flag.ContinueOnError)
	asJSON := flags.Bool("json", false, "print the raw status as JSON")
	if _, err := parsePermissive(flags, args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snaps, err := status.List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}

	if *asJSON {
		if snaps == nil {
			snaps = []status.Snapshot{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(snaps)
		return 0
	}
	if len(snaps) == 0 {
		fmt.Println("no running ngstone tunnels")
		return 0
	}
	fmt.Print(formatPS(snaps, time.Now()))
	return 0
}

// formatPS renders one row per tunnel.
func formatPS(snaps []status.Snapshot, now time.Time) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tCOMMAND\tTUNNEL\tKIND\tSTATE\tURL\tTARGET\tUP")
	for _, s := range snaps {
		up := now.Sub(s.Started).Round(time.Second)
		for _, t := range s.Tunnels {
			name := t.Name
			if name == "" {
				name = "-"
			}
			url := t.URL
			if url == "" {
				url = "-"
			}
			state := t.State
			if t.Err != "" && state != agent.StateOnline {
				state += " (" + t.Err + ")"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.PID, s.Command, name, t.Kind, state, url, t.Target, formatUptime(up))
		}
	}
	w.Flush()
	return b.String()
}

func formatUptime(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
