package ux

import (
	"fmt"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	hosts    []string
	ports    []string
	sessions []string
	logs     []string
	viewport viewport.Model
	ready    bool
}

func initialModel() model {
	return model{
		hosts:    []string{},
		ports:    []string{},
		sessions: []string{},
		logs:     []string{"[*] Gofence TUI initialized"},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.viewport = viewport.New(msg.Width, msg.Height)
		m.ready = true
	}
	return m, nil
}

func (m model) View() string {
	if !m.ready {
		return "Loading..."
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	panelStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)

	hostsPanel := panelStyle.Render(fmt.Sprintf("%s\n\n%s",
		headerStyle.Render("HOSTS"),
		joinLines(m.hosts),
	))

	portsPanel := panelStyle.Render(fmt.Sprintf("%s\n\n%s",
		headerStyle.Render("PORTS"),
		joinLines(m.ports),
	))

	sessionsPanel := panelStyle.Render(fmt.Sprintf("%s\n\n%s",
		headerStyle.Render("SESSIONS"),
		joinLines(m.sessions),
	))

	logsPanel := panelStyle.Render(fmt.Sprintf("%s\n\n%s",
		headerStyle.Render("LOG"),
		joinLines(m.logs),
	))

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		lipgloss.JoinVertical(lipgloss.Left, hostsPanel, portsPanel),
		lipgloss.JoinVertical(lipgloss.Left, sessionsPanel, logsPanel),
	)
}

func joinLines(items []string) string {
	if len(items) == 0 {
		return "  (empty)"
	}
	out := ""
	for _, item := range items {
		out += "  " + item + "\n"
	}
	return out
}

func RunTUI() error {
	p := tea.NewProgram(initialModel())
	_, err := p.Run()
	return err
}
