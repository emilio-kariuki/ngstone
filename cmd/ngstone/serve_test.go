package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func staticDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>app</h1>"), 0o644)
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0o644)
	os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("js"), 0o644)
	os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.txt"), []byte("secret"), 0o644)
	return dir
}

func get(t *testing.T, h http.Handler, p string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(b)
}

func TestStaticHandler(t *testing.T) {
	dir := staticDir(t)

	plain := newStaticHandler(dir, false)
	if code, body := get(t, plain, "/hello.txt"); code != 200 || body != "hello" {
		t.Fatalf("/hello.txt = %d %q", code, body)
	}
	if code, body := get(t, plain, "/"); code != 200 || body != "<h1>app</h1>" {
		t.Fatalf("/ = %d %q, want index.html", code, body)
	}
	if code, _ := get(t, plain, "/missing"); code != 404 {
		t.Fatalf("/missing = %d, want 404 without --spa", code)
	}
	if code, body := get(t, plain, "/../outside.txt"); code == 200 && body == "secret" {
		t.Fatal("path traversal escaped the directory")
	}

	spa := newStaticHandler(dir, true)
	if code, body := get(t, spa, "/dashboard/settings"); code != 200 || body != "<h1>app</h1>" {
		t.Fatalf("spa route = %d %q, want index.html", code, body)
	}
	if code, body := get(t, spa, "/assets/app.js"); code != 200 || body != "js" {
		t.Fatalf("spa asset = %d %q", code, body)
	}
	if code, _ := get(t, spa, "/missing.png"); code != 404 {
		t.Fatalf("spa missing asset = %d, want 404 (paths with an extension are not routes)", code)
	}
	if code, body := get(t, spa, "/hello.txt"); code != 200 || body != "hello" {
		t.Fatalf("spa file = %d %q", code, body)
	}
}
