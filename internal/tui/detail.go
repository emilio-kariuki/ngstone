package tui

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"ngstone/internal/inspect"
)

func hexPreview(data []byte, max int) string {
	if len(data) > max {
		data = data[:max]
	}
	return hex.Dump(data)
}

func renderHeaders(h http.Header) string {
	if len(h) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderBody(label string, header http.Header, raw []byte, capturedTruncated bool) string {
	d := inspect.Decode(header, raw)
	var b strings.Builder
	switch {
	case d.Binary:
		b.WriteString(hexPreview(d.Data, 512))
		if len(d.Data) > 512 {
			b.WriteString(fmt.Sprintf("\n[showing first 512 of %d bytes]", len(d.Data)))
		}
	case d.Err != "":
		b.WriteString(d.Err)
	default:
		b.WriteString(string(d.Data))
	}
	if capturedTruncated {
		b.WriteString(fmt.Sprintf("\n[%s body truncated at capture]", label))
	}
	if d.Truncated {
		b.WriteString("\n[decoded body truncated]")
	}
	return b.String()
}

func respStatusLine(ex *inspect.Exchange) string {
	if ex.Resp.Status == 0 {
		if ex.Err != "" {
			return errorStyle.Render(fmt.Sprintf("[error: %s]", ex.Err))
		}
		return helpStyle.Render("[no response]")
	}
	return statusStyle(ex.Resp.Status).Render(fmt.Sprintf("STATUS %d", ex.Resp.Status))
}

func buildDetail(ex *inspect.Exchange) string {
	if ex == nil {
		return ""
	}

	var b strings.Builder

	method := rowMethod(ex)
	reqLine := fmt.Sprintf("%s %s %s", method, ex.Req.URL, ex.Req.Proto)
	b.WriteString(methodStyle(method).Render(reqLine))
	b.WriteString("\n\n")

	b.WriteString(sectionHeaderStyle.Render("HEADERS"))
	b.WriteString("\n")
	b.WriteString(renderHeaders(ex.Req.Header))
	b.WriteString("\n\n")

	if ex.Kind == inspect.KindUpgrade {
		b.WriteString(fmt.Sprintf("client -> app: %s\n", fmtBytes(ex.BytesClientToApp)))
		b.WriteString(fmt.Sprintf("app -> client: %s\n", fmtBytes(ex.BytesAppToClient)))
		return b.String()
	}

	b.WriteString(sectionHeaderStyle.Render("BODY"))
	b.WriteString("\n")
	b.WriteString(renderBody("request", ex.Req.Header, ex.Req.Body, ex.Req.Truncated))
	b.WriteString("\n\n")

	b.WriteString(respStatusLine(ex))
	b.WriteString("\n\n")

	b.WriteString(sectionHeaderStyle.Render("HEADERS"))
	b.WriteString("\n")
	b.WriteString(renderHeaders(ex.Resp.Header))
	b.WriteString("\n\n")

	b.WriteString(sectionHeaderStyle.Render("BODY"))
	b.WriteString("\n")
	b.WriteString(renderBody("response", ex.Resp.Header, ex.Resp.Body, ex.Resp.Truncated))

	return b.String()
}
