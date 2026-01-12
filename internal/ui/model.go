package ui

import (
	"fmt"
	"strings"

	"github.com/statoon54/sscheck/internal/checker"

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
	completed int
	total     int
	target    string
	success   bool
}
type checkCompleteMsg struct {
	results []*checker.Result
}
type checkErrorMsg struct{}

// Model is the bubbletea model for the TUI
type Model struct {
	targets      []string
	results      []*checker.Result
	viewport     viewport.Model
	spinner      spinner.Model
	opts         *checker.Options
	progress     progress.Model
	completed    int
	total        int
	lastTarget   string
	lastSuccess  bool
	width        int
	height       int
	selected     int
	ready        bool
	checking     bool
	done         bool
	showAll      bool
	collapsed    bool // collapse details in Details tab
	activeTab    int  // 0 = Details, 1 = Score Summary, 2 = Rules
	tableCreated bool
	progressChan chan checkProgressMsg
}

// NewModel creates a new TUI model
func NewModel(targets []string, opts *checker.Options) *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	p := progress.New(progress.WithDefaultGradient())

	return &Model{
		targets:      targets,
		opts:         opts,
		spinner:      s,
		progress:     p,
		total:        len(targets),
		progressChan: make(chan checkProgressMsg, len(targets)),
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
		case "tab":
			if m.done {
				numTabs := m.getNumTabs()
				m.activeTab = (m.activeTab + 1) % numTabs
				m.updateViewportContent()
			}
		case "up", "k":
			if m.done && m.activeTab == 0 && m.selected > 0 {
				m.selected--
				m.viewport.SetContent(m.renderResults())
			}
		case "down", "j":
			if m.done && m.activeTab == 0 && m.selected < len(m.results)-1 {
				m.selected++
				m.viewport.SetContent(m.renderResults())
			}
		case "a":
			if m.done && m.activeTab == 0 {
				m.showAll = !m.showAll
				m.viewport.SetContent(m.renderResults())
			}
		case "c":
			if m.done && m.activeTab == 0 {
				m.collapsed = !m.collapsed
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
		return m, tea.Batch(m.runCheck(), m.waitForProgress())

	case checkProgressMsg:
		m.completed = msg.completed
		m.total = msg.total
		m.lastTarget = msg.target
		m.lastSuccess = msg.success
		cmds = append(cmds, m.spinner.Tick, m.waitForProgress())

	case checkCompleteMsg:
		m.checking = false
		m.done = true
		m.results = msg.results
		m.updateViewportContent()

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
		results := c.CheckAllWithProgress(
			m.targets,
			func(completed, total int, result *checker.Result) {
				success := result.Error == ""
				m.progressChan <- checkProgressMsg{
					completed: completed,
					total:     total,
					target:    result.Target,
					success:   success,
				}
			},
		)
		close(m.progressChan)
		return checkCompleteMsg{results: results}
	}
}

// waitForProgress returns a command that waits for progress updates
func (m *Model) waitForProgress() tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-m.progressChan
		if !ok {
			return nil
		}
		return msg
	}
}

// getNumTabs returns the number of tabs based on results
func (m *Model) getNumTabs() int {
	if len(m.results) > 1 {
		return 3 // Details, Scores, Rules
	}
	// Single result: Details and Rules (if rules exist)
	if m.hasAnyRules() {
		return 2 // Details, Rules
	}
	return 1 // Details only
}

// hasAnyRules checks if any result has scoring rules
func (m *Model) hasAnyRules() bool {
	for _, r := range m.results {
		if r.Error == "" && len(r.ScoreRules) > 0 {
			return true
		}
	}
	return false
}

// updateViewportContent updates the viewport based on active tab
func (m *Model) updateViewportContent() {
	switch m.activeTab {
	case 0:
		m.viewport.SetContent(m.renderResults())
	case 1:
		if len(m.results) > 1 {
			m.tableCreated = false
			m.viewport.SetContent(m.renderScoreSummary())
		} else {
			m.viewport.SetContent(m.renderRulesSummary())
		}
	case 2:
		m.viewport.SetContent(m.renderRulesSummary())
	}
}

func (m *Model) View() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("🔒 sscheck - Security Headers Check")
	b.WriteString(title + "\n\n")

	if m.checking {
		// Show progress
		fmt.Fprintf(&b, "%s Checking targets...\n\n", m.spinner.View())

		// Progress bar
		percent := float64(m.completed) / float64(m.total)
		b.WriteString(m.progress.ViewAs(percent) + "\n\n")

		// Progress count
		fmt.Fprintf(&b, "Progress: %d/%d completed\n", m.completed, m.total)

		// Last completed target
		if m.lastTarget != "" {
			icon := successStyle.Render("✓")
			if !m.lastSuccess {
				icon = errorStyle.Render("✗")
			}
			lastTarget := m.lastTarget
			if len(lastTarget) > 50 {
				lastTarget = lastTarget[:47] + "..."
			}
			fmt.Fprintf(&b, "Last: %s %s\n", icon, dimStyle.Render(lastTarget))
		}
	} else if m.done {
		// Show tabs if more than one tab available
		if m.getNumTabs() > 1 {
			b.WriteString(m.renderTabs())
			b.WriteString("\n")
		}

		// Show results summary only on Details tab
		if m.activeTab == 0 {
			b.WriteString(m.renderResultsSummary())
		} else {
			b.WriteString("\n")
		}
		b.WriteString("\n")

		if m.ready {
			b.WriteString(m.viewport.View())
		}

		b.WriteString("\n")
		if m.getNumTabs() > 1 {
			b.WriteString(dimStyle.Render("↑/↓: navigate • tab: switch view • a: toggle all • c: collapse • q: quit"))
		} else {
			b.WriteString(dimStyle.Render("↑/↓: navigate • a: toggle all • c: collapse • q: quit"))
		}
	}

	return b.String()
}

func (m *Model) renderTabs() string {
	var tabs []string

	// Active tab style with gradient
	activeTabBorder := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("205")).
		Bold(true).
		Foreground(lipgloss.AdaptiveColor{
			Light: "#FF00FF",
			Dark:  "#FF00FF",
		}).
		Background(lipgloss.AdaptiveColor{
			Light: "#1a1a2e",
			Dark:  "#1a1a2e",
		}).
		Padding(0, 2)

	// Inactive tab style
	inactiveTabStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Foreground(lipgloss.Color("240")).
		Padding(0, 2)

	renderTab := func(label string, isActive bool) string {
		if isActive {
			return activeTabBorder.Render(label)
		}
		return inactiveTabStyle.Render(label)
	}

	if len(m.results) > 1 {
		// Multiple results: Details, Scores, Rules
		tabs = append(tabs,
			renderTab("📋 Details", m.activeTab == 0),
			renderTab("📊 Scores", m.activeTab == 1),
			renderTab("📜 Rules", m.activeTab == 2),
		)
	} else {
		// Single result: Details, Rules
		tabs = append(tabs,
			renderTab("📋 Details", m.activeTab == 0),
			renderTab("📜 Rules", m.activeTab == 1),
		)
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
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

func (m *Model) renderScoreSummary() string {
	var b strings.Builder

	if len(m.results) == 0 {
		return "No results to display."
	}

	// Title
	b.WriteString(headerStyle.Render("📊 Observatory Score Summary"))
	b.WriteString("\n\n")

	// Styles pour le tableau
	headerLineStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39"))

	cellStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252"))

	borderStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	// Largeurs des colonnes
	const siteWidth = 40
	const scoreWidth = 10
	const gradeWidth = 10

	// En-têtes
	siteHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(siteWidth, lipgloss.Center, "Site"),
	)
	scoreHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(scoreWidth, lipgloss.Center, "Score"),
	)
	gradeHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(gradeWidth, lipgloss.Center, "Grade"),
	)

	b.WriteString(siteHeader + "  " + scoreHeader + "  " + gradeHeader + "\n")

	// Ligne de séparation
	separator := borderStyle.Render(strings.Repeat("─", siteWidth) + "  " +
		strings.Repeat("─", scoreWidth) + "  " +
		strings.Repeat("─", gradeWidth))
	b.WriteString(separator + "\n")

	// Lignes de données
	totalScore := 0
	validCount := 0
	minScore := 999
	maxScore := -1

	for _, r := range m.results {
		if r.Error != "" {
			site := cellStyle.Render(
				lipgloss.PlaceHorizontal(siteWidth, lipgloss.Left, truncate(r.Target, siteWidth-2)),
			)
			errorText := errorStyle.Render(
				lipgloss.PlaceHorizontal(scoreWidth, lipgloss.Center, "ERROR"),
			)
			dash := cellStyle.Render(lipgloss.PlaceHorizontal(gradeWidth, lipgloss.Center, "-"))
			b.WriteString(site + "  " + errorText + "  " + dash + "\n")
		} else {
			// Calculer les stats
			totalScore += r.Score
			validCount++
			if r.Score < minScore {
				minScore = r.Score
			}
			if r.Score > maxScore {
				maxScore = r.Score
			}

			// Afficher la ligne
			site := cellStyle.Render(lipgloss.PlaceHorizontal(siteWidth, lipgloss.Left, truncate(r.Target, siteWidth-2)))

			scoreColor := getScoreColor(r.Score)
			scoreText := lipgloss.NewStyle().
				Foreground(scoreColor).
				Bold(true).
				Render(lipgloss.PlaceHorizontal(scoreWidth, lipgloss.Center, fmt.Sprintf("%d", r.Score)))

			gradeText := lipgloss.NewStyle().
				Foreground(scoreColor).
				Bold(true).
				Render(lipgloss.PlaceHorizontal(gradeWidth, lipgloss.Center, r.Grade))

			b.WriteString(site + "  " + scoreText + "  " + gradeText + "\n")
		}
	}

	// Statistiques
	if validCount > 0 {
		avgScore := totalScore / validCount
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(
			"Average: %s  |  Min: %d  |  Max: %d\n",
			scoreStyle.
				Foreground(getScoreColor(avgScore)).
				Render(fmt.Sprintf("%d", avgScore)),
			minScore,
			maxScore,
		))
	}

	return b.String()
}

func (m *Model) renderRulesSummary() string {
	var b strings.Builder

	if len(m.results) == 0 {
		return "No results to display."
	}

	// Title
	b.WriteString(headerStyle.Render("📜 Applied Scoring Rules"))
	b.WriteString("\n\n")

	hasAnyRules := false
	for _, r := range m.results {
		if r.Error == "" && len(r.ScoreRules) > 0 {
			hasAnyRules = true
			break
		}
	}

	if !hasAnyRules {
		b.WriteString(dimStyle.Render("No scoring rules applied."))
		return b.String()
	}

	for _, r := range m.results {
		if r.Error != "" || len(r.ScoreRules) == 0 {
			continue
		}

		site := r.Target
		if len(site) > 60 {
			site = site[:57] + "..."
		}
		b.WriteString(headerStyle.Render(fmt.Sprintf("%s (Score: %d)", site, r.Score)))
		b.WriteString("\n")

		penalties := []checker.ScoreRule{}
		bonuses := []checker.ScoreRule{}
		bonusesNotApplied := []checker.ScoreRule{}

		for _, rule := range r.ScoreRules {
			if rule.Modifier < 0 {
				penalties = append(penalties, rule)
			} else if rule.Applied {
				bonuses = append(bonuses, rule)
			} else {
				bonusesNotApplied = append(bonusesNotApplied, rule)
			}
		}

		if len(penalties) > 0 {
			b.WriteString(errorStyle.Render("  Penalties:"))
			b.WriteString("\n")
			for _, rule := range penalties {
				b.WriteString(
					dimStyle.Render(
						fmt.Sprintf("    • %s: %d", rule.Description, rule.Modifier),
					),
				)
				b.WriteString("\n")
			}
		}

		if len(bonuses) > 0 {
			b.WriteString(successStyle.Render("  Bonuses:"))
			b.WriteString("\n")
			for _, rule := range bonuses {
				b.WriteString(
					dimStyle.Render(
						fmt.Sprintf("    • %s: +%d", rule.Description, rule.Modifier),
					),
				)
				b.WriteString("\n")
			}
		}

		if len(bonusesNotApplied) > 0 {
			b.WriteString(warningStyle.Render("  Bonuses not applied (score < 90):"))
			b.WriteString("\n")
			for _, rule := range bonusesNotApplied {
				b.WriteString(
					dimStyle.Render(
						fmt.Sprintf("    • %s: +%d", rule.Description, rule.Modifier),
					),
				)
				b.WriteString("\n")
			}
		}

		b.WriteString("\n")
	}

	return b.String()
}

func (m *Model) renderResults() string {
	var b strings.Builder

	// Collapsed mode: show compact table view
	if m.collapsed {
		return m.renderCollapsedResults()
	}

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

// renderCollapsedResults renders a compact table view of all results
func (m *Model) renderCollapsedResults() string {
	var b strings.Builder

	// Title
	b.WriteString(headerStyle.Render("📋 Sites Overview (collapsed)"))
	b.WriteString("\n\n")

	// Table header styles
	headerLineStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39"))

	cellStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252"))

	borderStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	// Column widths
	const siteWidth = 40
	const statusWidth = 8
	const safeWidth = 8
	const unsafeWidth = 8
	const scoreWidth = 8
	const gradeWidth = 8

	// Headers
	siteHeader := headerLineStyle.Render(lipgloss.PlaceHorizontal(siteWidth, lipgloss.Left, "Site"))
	statusHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(statusWidth, lipgloss.Center, "Status"),
	)
	safeHeader := headerLineStyle.Render(lipgloss.PlaceHorizontal(safeWidth, lipgloss.Center, "✓"))
	unsafeHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(unsafeWidth, lipgloss.Center, "✗"),
	)
	scoreHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(scoreWidth, lipgloss.Center, "Score"),
	)
	gradeHeader := headerLineStyle.Render(
		lipgloss.PlaceHorizontal(gradeWidth, lipgloss.Center, "Grade"),
	)

	b.WriteString(
		siteHeader + " " + statusHeader + " " + safeHeader + " " + unsafeHeader + " " + scoreHeader + " " + gradeHeader + "\n",
	)

	// Separator
	separator := borderStyle.Render(
		strings.Repeat("─", siteWidth) + " " +
			strings.Repeat("─", statusWidth) + " " +
			strings.Repeat("─", safeWidth) + " " +
			strings.Repeat("─", unsafeWidth) + " " +
			strings.Repeat("─", scoreWidth) + " " +
			strings.Repeat("─", gradeWidth))
	b.WriteString(separator + "\n")

	// Data rows
	for i, r := range m.results {
		prefix := "  "
		if i == m.selected {
			prefix = "▶ "
		}

		if r.Error != "" {
			site := cellStyle.Render(
				lipgloss.PlaceHorizontal(
					siteWidth,
					lipgloss.Left,
					prefix+truncate(r.Target, siteWidth-4),
				),
			)
			errorText := errorStyle.Render(
				lipgloss.PlaceHorizontal(statusWidth, lipgloss.Center, "ERROR"),
			)
			dash := cellStyle.Render(lipgloss.PlaceHorizontal(safeWidth, lipgloss.Center, "-"))
			b.WriteString(
				site + " " + errorText + " " + dash + " " + dash + " " + dash + " " + dash + "\n",
			)
		} else {
			site := cellStyle.Render(lipgloss.PlaceHorizontal(siteWidth, lipgloss.Left, prefix+truncate(r.Target, siteWidth-4)))

			statusColor := successStyle
			if r.StatusCode >= 400 {
				statusColor = errorStyle
			} else if r.StatusCode >= 300 {
				statusColor = warningStyle
			}
			status := statusColor.Render(lipgloss.PlaceHorizontal(statusWidth, lipgloss.Center, fmt.Sprintf("%d", r.StatusCode)))

			safe := successStyle.Render(lipgloss.PlaceHorizontal(safeWidth, lipgloss.Center, fmt.Sprintf("%d", r.SafeCount)))
			unsafe := errorStyle.Render(lipgloss.PlaceHorizontal(unsafeWidth, lipgloss.Center, fmt.Sprintf("%d", r.UnsafeCount)))

			scoreColor := getScoreColor(r.Score)
			score := lipgloss.NewStyle().Foreground(scoreColor).Bold(true).
				Render(lipgloss.PlaceHorizontal(scoreWidth, lipgloss.Center, fmt.Sprintf("%d", r.Score)))
			grade := lipgloss.NewStyle().Foreground(scoreColor).Bold(true).
				Render(lipgloss.PlaceHorizontal(gradeWidth, lipgloss.Center, r.Grade))

			b.WriteString(site + " " + status + " " + safe + " " + unsafe + " " + score + " " + grade + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Press 'c' to expand details"))

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
