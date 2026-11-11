package policy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxRedirectURL        = 2048
	defaultRedirectStatus = http.StatusFound
)

func (r *Rule) validateRedirect() error {
	if r.Action != ActionRedirect {
		if r.RedirectURL != "" || r.RedirectStatus != 0 {
			return errors.New("redirect_url and redirect_status require action redirect")
		}
		return nil
	}
	if r.RedirectURL == "" {
		return errors.New("redirect requires redirect_url")
	}
	if len(r.RedirectURL) > maxRedirectURL {
		return fmt.Errorf("redirect_url exceeds %d bytes", maxRedirectURL)
	}
	if containsControl(r.RedirectURL) || strings.ContainsAny(r.RedirectURL, " \\#") {
		return errors.New("redirect_url contains invalid characters")
	}
	if strings.HasPrefix(r.RedirectURL, "//") || !validRedirectTarget(collapseLeadingSlashes(substitutePath(r.RedirectURL, "/x"))) {
		return errors.New("redirect_url must be an absolute path or an http(s) URL")
	}
	switch r.RedirectStatus {
	case 0:
		r.RedirectStatus = defaultRedirectStatus
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return errors.New("redirect_status must be 301, 302, 307 or 308")
	}
	return nil
}

func validRedirectTarget(target string) bool {
	if strings.HasPrefix(target, "/") {
		if strings.HasPrefix(target, "//") {
			return false
		}
		_, err := url.Parse(target)
		return err == nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil
}

func substitutePath(target, path string) string {
	target = strings.ReplaceAll(target, "${path}", path)
	return strings.ReplaceAll(target, "$path", path)
}

func collapseLeadingSlashes(target string) string {
	if target == "" {
		return "/"
	}
	if strings.HasPrefix(target, "/") {
		return "/" + strings.TrimLeft(target, "/")
	}
	return target
}

func (r *Rule) redirectTarget(req *http.Request) string {
	rawPath := "/"
	rawQuery := ""
	if req != nil && req.URL != nil {
		rawPath = req.URL.Path
		rawQuery = req.URL.RawQuery
	}
	normalized := normalizePath(rawPath)
	rest := normalized
	if r.PathPrefix != "" && r.PathPrefix != "/" {
		rest = strings.TrimPrefix(normalized, r.PathPrefix)
	}
	if strings.HasSuffix(rawPath, "/") && !strings.HasSuffix(rest, "/") {
		rest += "/"
	}
	target := substitutePath(r.RedirectURL, (&url.URL{Path: rest}).EscapedPath())
	target = collapseLeadingSlashes(target)
	if rawQuery != "" {
		if strings.Contains(target, "?") {
			target += "&" + rawQuery
		} else {
			target += "?" + rawQuery
		}
	}
	return target
}
