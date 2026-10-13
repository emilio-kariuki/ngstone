package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"ngstone/internal/agent"
	"ngstone/internal/config"
)

// cmdServe shares a directory of files: it starts a file server on a
// loopback port and runs the same tunnel as `ngstone port` against it.
func cmdServe(args []string) int {
	fs, pf := newPortFlagSet()
	fs.Init("serve", fs.ErrorHandling())
	spa := fs.Bool("spa", false, "single-page app mode: serve index.html for paths that have no file and no extension")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) > 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone serve [dir] [--subdomain name] [--spa]")
		return 2
	}
	dir := "."
	if len(positionals) == 1 {
		dir = positionals[0]
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "ngstone: %s is not a directory\n", dir)
		return 2
	}
	if *spa {
		if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: --spa needs an index.html in %s\n", dir)
			return 2
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	token, err := resolveToken(pf.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	basicAuthPairs, err := resolveBasicAuthPairs(pf.basicAuth, pf.basicAuthFile, os.Getenv("NGSTONE_BASIC_AUTH"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	basicAuthDigests, err := parseBasicAuthCreds(basicAuthPairs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	allowCIDRs, err := parseAllowCIDRs(pf.allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr, err := serveFiles(ctx, dir, *spa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}

	acfg := agent.Config{
		ControlAddr: resolveServer(pf.server, cfg),
		Token:       token,
		Subdomain:   pf.subdomain,
		TargetURL:   "http://" + addr,
		HostHeader:  pf.hostHeader,
		InstanceID:  pf.instanceID,

		BasicAuthSHA256: basicAuthDigests,
		AllowCIDRs:      allowCIDRs,

		Insecure:   pf.insecure,
		ServerName: pf.serverName,
		Pin:        pf.pin,
	}

	fmt.Fprintf(os.Stderr, "ngstone: serving %s on %s\n", dir, addr)
	if shouldUseTUI(pf.noTUI) {
		return runPortTUI(ctx, acfg)
	}
	return runPortPlain(ctx, acfg)
}

// serveFiles starts the file server on a random loopback port and returns
// its address. It stops when ctx ends.
func serveFiles(ctx context.Context, dir string, spa bool) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listening for the file server: %w", err)
	}
	srv := &http.Server{Handler: newStaticHandler(dir, spa)}
	go srv.Serve(ln)
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	return ln.Addr().String(), nil
}

// newStaticHandler serves dir. With spa, a request whose path names no
// file and has no extension gets index.html, so client-side routes work
// after a reload.
func newStaticHandler(dir string, spa bool) http.Handler {
	files := http.FileServer(http.Dir(dir))
	if !spa {
		return files
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if path.Ext(clean) == "" {
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(clean))); errors.Is(err, os.ErrNotExist) {
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/"
				r2.URL.RawPath = ""
				files.ServeHTTP(w, r2)
				return
			}
		}
		files.ServeHTTP(w, r)
	})
}
