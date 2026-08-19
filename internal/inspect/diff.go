package inspect

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const maxDiffLines = 2048

func DiffResponses(original, replay *Exchange) (string, error) {
	if original == nil || replay == nil {
		return "", ErrNotFound
	}

	var b strings.Builder
	b.WriteString("RESPONSE DIFF\n")
	b.WriteString(fmt.Sprintf("original %s\nreplay   %s\n", original.ID, replay.ID))
	changed := false
	changed = appendDiffSection(&b, "STATUS", []string{responseStatus(original)}, []string{responseStatus(replay)}) || changed
	changed = appendDiffSection(&b, "HEADERS", responseHeaders(original.Resp.Header), responseHeaders(replay.Resp.Header)) || changed
	changed = appendDiffSection(&b, "BODY", responseBodyLines(original), responseBodyLines(replay)) || changed
	if !changed {
		b.WriteString("\n(no response differences)\n")
	}
	return b.String(), nil
}

func responseStatus(ex *Exchange) string {
	if ex.Resp.Status == 0 {
		if ex.Err != "" {
			return "error: " + ex.Err
		}
		return "no response"
	}
	return fmt.Sprintf("%d %s", ex.Resp.Status, http.StatusText(ex.Resp.Status))
}

func responseHeaders(header http.Header) []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(header))
	for _, key := range keys {
		values := header.Values(key)
		if len(values) == 0 {
			lines = append(lines, key+":")
			continue
		}
		for _, value := range values {
			lines = append(lines, key+": "+value)
		}
	}
	return lines
}

func responseBodyLines(ex *Exchange) []string {
	data := ex.Resp.Body
	decoded := Decode(ex.Resp.Header, data)
	if decoded.Err == "" && !decoded.Binary {
		data = decoded.Data
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) > BodyCap {
		data = data[:BodyCap]
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return []string{fmt.Sprintf("<binary body: %d bytes>", ex.Resp.BodySize)}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > maxDiffLines {
		lines = append(lines[:maxDiffLines], fmt.Sprintf("<body diff truncated at %d lines>", maxDiffLines))
	}
	return lines
}

func appendDiffSection(b *strings.Builder, title string, original, replay []string) bool {
	diff := lineDiff(original, replay)
	if len(diff) == 0 {
		return false
	}
	b.WriteString("\n@@ ")
	b.WriteString(title)
	b.WriteString(" @@\n")
	for _, line := range diff {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return true
}

func lineDiff(original, replay []string) []string {
	if len(original) == 0 && len(replay) == 0 {
		return nil
	}
	if len(original) == len(replay) {
		same := true
		for i := range original {
			if original[i] != replay[i] {
				same = false
				break
			}
		}
		if same {
			return nil
		}
	}
	if len(original)*len(replay) > maxDiffLines*maxDiffLines {
		return appendPrefixed(appendPrefixed(nil, "-", original), "+", replay)
	}
	dp := make([][]int, len(original)+1)
	for i := range dp {
		dp[i] = make([]int, len(replay)+1)
	}
	for i := len(original) - 1; i >= 0; i-- {
		for j := len(replay) - 1; j >= 0; j-- {
			if original[i] == replay[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	out := make([]string, 0)
	for i, j := 0, 0; i < len(original) || j < len(replay); {
		switch {
		case i < len(original) && j < len(replay) && original[i] == replay[j]:
			out = append(out, "  "+original[i])
			i++
			j++
		case j < len(replay) && (i == len(original) || dp[i][j+1] >= dp[i+1][j]):
			out = append(out, "+ "+replay[j])
			j++
		default:
			out = append(out, "- "+original[i])
			i++
		}
	}
	return out
}

func appendPrefixed(dst []string, prefix string, lines []string) []string {
	for _, line := range lines {
		dst = append(dst, prefix+" "+line)
	}
	return dst
}
