package tui

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func copyToClipboard(text string) error {
	command, args, ok := clipboardCommand()
	if !ok {
		return errors.New("no supported clipboard command found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func clipboardCommand() (string, []string, bool) {
	switch runtime.GOOS {
	case "darwin":
		return "pbcopy", nil, true
	case "windows":
		return "clip", nil, true
	case "linux":
		if _, err := exec.LookPath("wl-copy"); err == nil {
			return "wl-copy", nil, true
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			return "xclip", []string{"-selection", "clipboard"}, true
		}
	}
	return "", nil, false
}
