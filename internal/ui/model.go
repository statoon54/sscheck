package ui

import (
	"fmt"
	"strings"

	"sscheck/internal/checker"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	scoreStyle = lipgloss.NewStyle().
			Bold(true)
)

// Messages
type checkStartMsg struct{}
type checkProgressMsg struct {
	current int
}
type checkCompleteMsg struct {
	results []*checker.Result
}
type checkErrorMsg struct{}

// Model is the bubbletea model for the TUI
type Model struct {
	targets  []string
	results  []*checker.Result
	viewport viewport.Model
	spinner  spinner.Model
	opts     *checker.Options
	progress progress.Model
	current  int
	width    int
	height   int
	selected int
	ready    bool
	checking bool
	done     bool
	showAll  bool
}

// NewModel creates a new TUI model
func NewModel(targets []string, opts *checker.Options) *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	p := progress.New(progress.WithDefaultGradient())

	return &Model{
		targets:  targets,
		opts:     opts,
		spinner:  s,
		progress: p,
	}
}

// Init initializes the model
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.startCheck())
}

// startCheck initiates the checking process
func (m *Model) startCheck() tea.Cmd {
	return func() tea.Msg {
		return checkStartMsg{}
	}
}

// Update handles incoming messages and updates the model state
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.done && m.selected > 0 {
				m.selected--
				m.viewport.SetContent(m.renderResults())
			}
		case "down", "j":
			if m.done && m.selected < len(m.results)-1 {
				m.selected++
				m.viewport.SetContent(m.renderResults())
			}
		case "a":
			if m.done {
				m.showAll = !m.showAll
				m.viewport.SetContent(m.renderResults())
			}
		case "enter":
			// Toggle detail view
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 20
		if !m.ready {
			m.viewport = viewport.New(msg.Width-4, msg.Height-10)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 4
			m.viewport.Height = msg.Height - 10
		}

	case checkStartMsg:
		m.checking = true
		cmd := m.runCheck()
		return m, cmd

	case checkProgressMsg:
		m.current = msg.current
		cmds = append(cmds, m.spinner.Tick)

	case checkCompleteMsg:
		m.checking = false
		m.done = true
		m.results = msg.results
		m.viewport.SetContent(m.renderResults())

	case checkErrorMsg:
		m.checking = false

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		if p, ok := progressModel.(progress.Model); ok {
			m.progress = p
		}
		cmds = append(cmds, cmd)
	}

	// Update viewport
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) runCheck() tea.Cmd {
	return func() tea.Msg {
		c := checker.New(m.opts)
		results := c.CheckAll(m.targets)
		return checkCompleteMsg{results: results}
	}
}

func (m *Model) View() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("🔒 sscheck - Security Headers Check")
	b.WriteString(title + "\n\n")

	if m.checking {
		// Show progress
		fmt.Fprintf(&b, "%s Checking %d target(s)...\n\n", m.spinner.View(), len(m.targets))
		percent := float64(m.current) / float64(len(m.targets))
		b.WriteString(m.progress.ViewAs(percent) + "\n")
	} else if m.done {
		// Show results
		b.WriteString(m.renderResultsSummary())
		b.WriteString("\n")

		if m.ready {
			b.WriteString(m.viewport.View())
		}

		b.WriteString("\n")
		b.WriteString(dimStyle.Render("↑/↓: navigate • a: toggle all headers • q: quit"))
	}

	return b.String()
}

func (m *Model) renderResultsSummary() string {
	var b strings.Builder

	totalSafe := 0
	totalUnsafe := 0
	totalScore := 0
	for _, r := range m.results {
		totalSafe += r.SafeCount
		totalUnsafe += r.UnsafeCount
		totalScore += r.Score
	}

	avgScore := 0
	if len(m.results) > 0 {
		avgScore = totalScore / len(m.results)
	}

	fmt.Fprintf(&b, "Checked %d target(s) | Avg Score: %d\n", len(m.results), avgScore)
	b.WriteString(successStyle.Render(fmt.Sprintf("✓ %d security headers present", totalSafe)))
	b.WriteString(" | ")
	b.WriteString(errorStyle.Render(fmt.Sprintf("✗ %d security headers missing", totalUnsafe)))
	b.WriteString("\n")

	return b.String()
}

func (m *Model) renderResults() string {
	var b strings.Builder

	for i, result := range m.results {
		selected := i == m.selected

		// Result header
		prefix := "  "
		if selected {
			prefix = "▶ "
		}

		if result.Error != "" {
			b.WriteString(
				errorStyle.Render(fmt.Sprintf("%s✗ %s: %s", prefix, result.Target, result.Error)),
			)
			b.WriteString("\n")
			continue
		}

		statusColor := successStyle
		if result.UnsafeCount > 5 {
			statusColor = errorStyle
		} else if result.UnsafeCount > 2 {
			statusColor = warningStyle
		}

		b.WriteString(headerStyle.Render(fmt.Sprintf("%s%s", prefix, result.Target)))
		b.WriteString("\n")
		fmt.Fprintf(&b, "   Effective URL: %s\n", infoStyle.Render(result.EffectiveURL))
		fmt.Fprintf(&b, "   Status: %s | ",
			statusColor.Render(fmt.Sprintf("%d", result.StatusCode)))
		b.WriteString(successStyle.Render(fmt.Sprintf("✓ %d", result.SafeCount)))
		b.WriteString(" | ")
		b.WriteString(errorStyle.Render(fmt.Sprintf("✗ %d", result.UnsafeCount)))
		b.WriteString("\n")
		// Score on its own line with icon and bold style
		scoreStyleColored := scoreStyle.Foreground(getScoreColor(result.Score))
		fmt.Fprintf(
			&b,
			"   📊 %s\n",
			scoreStyleColored.Render(
				fmt.Sprintf("Observatory Score: %d | Grade: %s", result.Score, result.Grade),
			),
		)

		if selected || m.showAll {
			// Present headers
			if len(result.PresentHeaders) > 0 {
				b.WriteString("\n   " + successStyle.Render("Present Headers:") + "\n")
				for _, h := range result.PresentHeaders {
					status := "✓"
					style := successStyle
					switch h.Status {
					case "warning":
						status = "⚠"
						style = warningStyle
					case "error":
						status = "✗"
						style = errorStyle
					}
					fmt.Fprintf(&b, "   %s %s: %s\n",
						style.Render(status),
						h.Name,
						dimStyle.Render(truncate(h.Value, 60)))

					// Show CSP issues if any
					if len(h.Issues) > 0 {
						for _, issue := range h.Issues {
							fmt.Fprintf(&b, "      %s %s\n",
								warningStyle.Render("↳"),
								dimStyle.Render(issue))
						}
					}
				}
			}

			// Missing headers
			if len(result.MissingHeaders) > 0 {
				b.WriteString("\n   " + errorStyle.Render("Missing Headers:") + "\n")
				for _, h := range result.MissingHeaders {
					icon := "✗"
					style := errorStyle
					switch h.Severity {
					case "warning":
						icon = "⚠"
						style = warningStyle
					case "deprecated":
						icon = "○"
						style = dimStyle
					}
					fmt.Fprintf(&b, "   %s %s\n", style.Render(icon), h.Name)
				}
			}

			// Info headers
			if len(result.InfoHeaders) > 0 {
				b.WriteString("\n   " + warningStyle.Render("Information Disclosure:") + "\n")
				for _, h := range result.InfoHeaders {
					fmt.Fprintf(&b, "   ⚠ %s: %s\n", h.Name, dimStyle.Render(h.Value))
				}
			}

			// Cache headers
			if len(result.CacheHeaders) > 0 {
				b.WriteString("\n   " + infoStyle.Render("Cache Headers:") + "\n")
				for _, h := range result.CacheHeaders {
					fmt.Fprintf(&b, "   ℹ %s: %s\n", h.Name, dimStyle.Render(h.Value))
				}
			}

			// Cookie analysis
			if len(result.Cookies) > 0 {
				b.WriteString("\n   " + infoStyle.Render("Cookies:") + "\n")
				for _, c := range result.Cookies {
					flags := []string{}
					if c.Secure {
						flags = append(flags, successStyle.Render("Secure"))
					}
					if c.HttpOnly {
						flags = append(flags, successStyle.Render("HttpOnly"))
					}
					if c.SameSite != "" {
						flags = append(flags, infoStyle.Render("SameSite="+c.SameSite))
					}
					flagStr := ""
					if len(flags) > 0 {
						flagStr = " [" + strings.Join(flags, ", ") + "]"
					}
					fmt.Fprintf(&b, "   🍪 %s%s\n", c.Name, flagStr)
					for _, issue := range c.Issues {
						fmt.Fprintf(&b, "      %s %s\n",
							warningStyle.Render("↳"),
							dimStyle.Render(issue))
					}
				}
			}

			// CORS analysis
			if result.CORS != nil {
				b.WriteString("\n   " + infoStyle.Render("CORS Configuration:") + "\n")
				fmt.Fprintf(&b, "   🌐 Allow-Origin: %s\n", result.CORS.AllowOrigin)
				if result.CORS.AllowCredentials {
					fmt.Fprintf(&b, "   🌐 Allow-Credentials: %s\n", warningStyle.Render("true"))
				}
				if result.CORS.AllowMethods != "" {
					fmt.Fprintf(
						&b,
						"   🌐 Allow-Methods: %s\n",
						dimStyle.Render(result.CORS.AllowMethods),
					)
				}
				for _, issue := range result.CORS.Issues {
					fmt.Fprintf(&b, "      %s %s\n",
						errorStyle.Render("↳"),
						dimStyle.Render(issue))
				}
			}
		}

		b.WriteString("\n")
	}

	return b.String()
}

// truncate shortens a string to maxLen, adding "..." if truncated
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// getScoreColor returns the appropriate color for the score
func getScoreColor(score int) lipgloss.Color {
	switch {
	case score >= 100:
		return lipgloss.Color("42") // Green
	case score >= 85:
		return lipgloss.Color("46") // Light green
	case score >= 70:
		return lipgloss.Color("226") // Yellow
	case score >= 50:
		return lipgloss.Color("208") // Orange
	default:
		return lipgloss.Color("196") // Red
	}
}

// RunInteractive starts the interactive TUI
func RunInteractive(targets []string, opts *checker.Options) {
	p := tea.NewProgram(NewModel(targets, opts), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
	}
}
