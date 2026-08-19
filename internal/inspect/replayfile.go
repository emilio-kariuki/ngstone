package inspect

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const replayFileVersion = 1

type replayFile struct {
	Version   int           `json:"version"`
	CreatedAt time.Time     `json:"created_at"`
	SourceID  string        `json:"source_id,omitempty"`
	Request   replayRequest `json:"request"`
}

type replayRequest struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Headers    http.Header `json:"headers,omitempty"`
	BodyBase64 string      `json:"body_base64,omitempty"`
	BodySize   int64       `json:"body_size,omitempty"`
}

func SaveReplay(path string, ex *Exchange) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("inspect: replay output path is required")
	}
	if ex == nil {
		return ErrNotFound
	}
	if ex.Kind == KindUpgrade {
		return ErrNotReplayable
	}
	if ex.Req.Truncated {
		return ErrTruncatedBody
	}
	if strings.TrimSpace(ex.Req.URL) == "" {
		return errors.New("inspect: replay request URL is required")
	}

	doc := replayFile{
		Version:   replayFileVersion,
		CreatedAt: ex.Start.UTC(),
		SourceID:  ex.ID,
		Request: replayRequest{
			Method:   ex.Req.Method,
			URL:      ex.Req.URL,
			Headers:  ex.Req.Header.Clone(),
			BodySize: ex.Req.BodySize,
		},
	}
	if len(ex.Req.Body) > 0 {
		doc.Request.BodyBase64 = base64.StdEncoding.EncodeToString(ex.Req.Body)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("inspect: encoding replay file: %w", err)
	}
	return writePrivateFile(path, data)
}

func LoadReplay(path string) (*Exchange, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("inspect: replay input path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inspect: reading replay file: %w", err)
	}
	var doc replayFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("inspect: decoding replay file: %w", err)
	}
	if doc.Version != replayFileVersion {
		return nil, fmt.Errorf("inspect: unsupported replay file version %d", doc.Version)
	}
	if strings.TrimSpace(doc.Request.URL) == "" {
		return nil, errors.New("inspect: replay file request URL is required")
	}
	body, err := base64.StdEncoding.DecodeString(doc.Request.BodyBase64)
	if err != nil {
		return nil, fmt.Errorf("inspect: decoding replay body: %w", err)
	}
	start := doc.CreatedAt
	if start.IsZero() {
		start = time.Now()
	}
	return &Exchange{
		ID:    newID(),
		Kind:  KindHTTP,
		Start: start,
		Req: CapturedReq{
			Method:   doc.Request.Method,
			URL:      doc.Request.URL,
			Header:   doc.Request.Headers.Clone(),
			Body:     body,
			BodySize: doc.Request.BodySize,
		},
	}, nil
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("inspect: creating %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("inspect: protecting %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("inspect: writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("inspect: closing %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("inspect: replacing %s: %w", path, err)
	}
	renamed = true
	return nil
}
