package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ngstone/internal/inspect"
)

type replayJSONOutput struct {
	Type       string      `json:"type"`
	File       string      `json:"file"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Target     string      `json:"target,omitempty"`
	Status     int         `json:"status"`
	Headers    http.Header `json:"headers,omitempty"`
	BodyBase64 string      `json:"body_base64,omitempty"`
	DurationMS int64       `json:"duration_ms"`
	Error      string      `json:"error,omitempty"`
}

func cmdReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	targetFlag := fs.String("target", "", "local target port or URL (required unless --curl is used)")
	jsonOutput := fs.Bool("json", false, "emit one JSON result")
	curlOutput := fs.Bool("curl", false, "print a cURL command instead of sending the request")
	includeSensitive := fs.Bool("include-sensitive", false, "include sensitive headers in --curl output")
	timeout := fs.Duration("timeout", 30*time.Second, "maximum time to wait for the replay response")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone replay <file> --target <port|url> [--json]")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "ngstone: --timeout must be positive")
		return 2
	}

	ex, err := inspect.LoadReplay(positionals[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}

	var target *url.URL
	if *targetFlag != "" {
		targetRaw, resolveErr := resolveTargetURL(*targetFlag)
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "ngstone: %v\n", resolveErr)
			return 2
		}
		target, err = url.Parse(targetRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: invalid replay target: %v\n", err)
			return 2
		}
	}

	if *curlOutput {
		command, curlErr := inspect.BuildCurl(ex, inspect.CurlOptions{
			IncludeSensitive: *includeSensitive,
			Target:           target,
		})
		if curlErr != nil {
			fmt.Fprintf(os.Stderr, "ngstone: %v\n", curlErr)
			return 1
		}
		fmt.Println(command)
		return 0
	}
	if target == nil {
		fmt.Fprintln(os.Stderr, "ngstone: --target is required unless --curl is used")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	out, replayErr := inspect.Replay(ctx, ex, target, http.DefaultTransport, nil)
	if *jsonOutput {
		return writeReplayJSON(positionals[0], target, out, replayErr)
	}
	if out != nil {
		if out.Resp.Status != 0 {
			fmt.Printf("%s %d %s (%s)\n", out.Req.Method, out.Resp.Status, http.StatusText(out.Resp.Status), out.Duration.Round(time.Millisecond))
		} else {
			fmt.Printf("%s failed (%s)\n", out.Req.Method, out.Duration.Round(time.Millisecond))
		}
		if len(out.Resp.Body) > 0 {
			_, _ = os.Stdout.Write(out.Resp.Body)
			if out.Resp.Body[len(out.Resp.Body)-1] != '\n' {
				fmt.Println()
			}
		}
	}
	if replayErr != nil {
		fmt.Fprintf(os.Stderr, "ngstone: replay failed: %v\n", replayErr)
		return 1
	}
	return 0
}

func writeReplayJSON(path string, target *url.URL, ex *inspect.Exchange, replayErr error) int {
	result := replayJSONOutput{Type: "replay", File: path}
	if target != nil {
		result.Target = target.String()
	}
	if ex != nil {
		result.Method = ex.Req.Method
		result.URL = ex.Req.URL
		result.Status = ex.Resp.Status
		result.Headers = ex.Resp.Header
		result.BodyBase64 = base64.StdEncoding.EncodeToString(ex.Resp.Body)
		result.DurationMS = ex.Duration.Milliseconds()
	}
	if replayErr != nil {
		result.Error = replayErr.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: writing replay JSON: %v\n", err)
		return 1
	}
	if replayErr != nil {
		return 1
	}
	return 0
}
