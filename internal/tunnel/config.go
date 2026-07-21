package tunnel

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

type slogYamuxLogger struct {
	l *slog.Logger
}

func (s *slogYamuxLogger) Print(v ...interface{}) {
	s.l.Debug(strings.TrimSpace(fmt.Sprint(v...)))
}

func (s *slogYamuxLogger) Printf(format string, v ...interface{}) {
	s.l.Debug(strings.TrimSpace(fmt.Sprintf(format, v...)))
}

func (s *slogYamuxLogger) Println(v ...interface{}) {
	s.l.Debug(strings.TrimSpace(fmt.Sprintln(v...)))
}

func newYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 512
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 45 * time.Second
	cfg.MaxStreamWindowSize = 1 << 20
	cfg.LogOutput = nil
	cfg.Logger = &slogYamuxLogger{l: slog.Default()}
	return cfg
}
