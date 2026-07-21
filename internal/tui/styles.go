package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	colorMethodGET      = lipgloss.Color("39")
	colorMethodPOST     = lipgloss.Color("42")
	colorMethodPUTPATCH = lipgloss.Color("220")
	colorMethodDELETE   = lipgloss.Color("196")
	colorMethodGray     = lipgloss.Color("245")
	colorMethodWS       = lipgloss.Color("201")

	colorStatus2xx = lipgloss.Color("42")
	colorStatus3xx = lipgloss.Color("39")
	colorStatus4xx = lipgloss.Color("214")
	colorStatus5xx = lipgloss.Color("196")
	colorStatus101 = lipgloss.Color("135")

	colorMuted       = lipgloss.Color("245")
	colorError       = lipgloss.Color("196")
	colorAccent      = lipgloss.Color("39")
	colorHighlightBg = lipgloss.Color("237")
)

var (
	headerTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	sectionHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	listHeaderStyle    = lipgloss.NewStyle().Foreground(colorMuted)
	footerStyle        = lipgloss.NewStyle().Foreground(colorMuted)
	errorStyle         = lipgloss.NewStyle().Foreground(colorError)
	helpStyle          = lipgloss.NewStyle().Foreground(colorMuted)
)

func methodStyle(method string) lipgloss.Style {
	switch strings.ToUpper(method) {
	case "GET":
		return lipgloss.NewStyle().Foreground(colorMethodGET)
	case "POST":
		return lipgloss.NewStyle().Foreground(colorMethodPOST)
	case "PUT", "PATCH":
		return lipgloss.NewStyle().Foreground(colorMethodPUTPATCH)
	case "DELETE":
		return lipgloss.NewStyle().Foreground(colorMethodDELETE)
	case "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return lipgloss.NewStyle().Foreground(colorMethodGray)
	case "WS":
		return lipgloss.NewStyle().Foreground(colorMethodWS)
	default:
		return lipgloss.NewStyle().Foreground(colorMethodGray)
	}
}

func statusStyle(status int) lipgloss.Style {
	switch {
	case status == 101:
		return lipgloss.NewStyle().Foreground(colorStatus101)
	case status >= 200 && status < 300:
		return lipgloss.NewStyle().Foreground(colorStatus2xx)
	case status >= 300 && status < 400:
		return lipgloss.NewStyle().Foreground(colorStatus3xx)
	case status >= 400 && status < 500:
		return lipgloss.NewStyle().Foreground(colorStatus4xx)
	case status >= 500:
		return lipgloss.NewStyle().Foreground(colorStatus5xx)
	default:
		return lipgloss.NewStyle().Foreground(colorMuted)
	}
}

func stateStyle(state string) lipgloss.Style {
	switch state {
	case "online":
		return lipgloss.NewStyle().Foreground(colorStatus2xx)
	case "connecting", "reconnecting":
		return lipgloss.NewStyle().Foreground(colorStatus4xx)
	case "evicted":
		return lipgloss.NewStyle().Foreground(colorError)
	default:
		return lipgloss.NewStyle().Foreground(colorMuted)
	}
}
