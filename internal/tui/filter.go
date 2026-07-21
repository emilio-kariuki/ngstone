package tui

import (
	"regexp"
	"strconv"
	"strings"

	"ngstone/internal/inspect"
)

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

var statusClassRe = regexp.MustCompile(`^[1-5]xx$`)

type filterKind int

const (
	filterNone filterKind = iota
	filterMethod
	filterStatusClass
	filterSubstring
)

func classifyFilter(q string) (filterKind, string) {
	q = strings.TrimSpace(q)
	if q == "" {
		return filterNone, ""
	}
	upper := strings.ToUpper(q)
	if httpMethods[upper] || upper == "WS" {
		return filterMethod, upper
	}
	lower := strings.ToLower(q)
	if statusClassRe.MatchString(lower) {
		return filterStatusClass, lower[:1]
	}
	return filterSubstring, lower
}

func matchFilter(q string, ex *inspect.Exchange) bool {
	kind, val := classifyFilter(q)
	switch kind {
	case filterNone:
		return true
	case filterMethod:
		method := ex.Req.Method
		if ex.Kind == inspect.KindUpgrade {
			method = "WS"
		}
		return strings.EqualFold(method, val)
	case filterStatusClass:
		if ex.Resp.Status == 0 {
			return false
		}
		return strconv.Itoa(ex.Resp.Status/100) == val
	default:
		return strings.Contains(strings.ToLower(rowPath(ex.Req.URL)), val)
	}
}
