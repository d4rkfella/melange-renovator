package dashboard

import (
	"context"
	"fmt"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/repo"
	"github.com/d4rkfella/melange-renovator/internal/report"
)

// DashboardMarker is embedded in the body to uniquely identify the issue.
const DashboardMarker = "<!-- melange-renovator: dependency-dashboard -->"

// Issue is a trimmed view of a GitHub issue.
type Issue struct {
	Number int
	Title  string
	Body   string
	State  string
	Author string
}

// IssueClient interface with title, body, and state update support.
type IssueClient interface {
	ListIssues(ctx context.Context, owner, repo, state string, page int) ([]Issue, error)
	CreateIssue(ctx context.Context, owner, repo, title, body string) error
	EditIssue(ctx context.Context, owner, repo string, number int, title, body, state *string) error
}

// Manager implements app.DashboardManager.
type Manager struct {
	Client    IssueClient
	AutoClose bool
}

// NewManager builds a Manager with the specified IssueClient.
func NewManager(client IssueClient) *Manager {
	return &Manager{Client: client}
}

// ParseActions extracts checkable dashboard actions from raw markdown text.
func ParseActions(body string) Actions {
	if body == "" {
		return Actions{}
	}
	return parseDashboardBody(body)
}

func isDashboardIssue(iss Issue, targetTitle, botLogin string) bool {
	if botLogin != "" && !strings.EqualFold(iss.Author, botLogin) {
		return false
	}

	if strings.Contains(iss.Body, DashboardMarker) {
		return true
	}
	return iss.Title == targetTitle
}

func (m *Manager) listAllIssues(ctx context.Context, owner, repoName, state string) ([]Issue, error) {
	var allIssues []Issue
	page := 1

	for {
		issues, err := m.Client.ListIssues(ctx, owner, repoName, state, page)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if len(issues) == 0 {
			break
		}
		allIssues = append(allIssues, issues...)

		if len(issues) < 100 {
			break
		}
		page++
	}

	return allIssues, nil
}

// FindOpen queries open repository issues to locate an active dashboard issue handle.
func (m *Manager) FindOpen(ctx context.Context, repo repo.Identifier, title, bot string) (*Issue, error) {
	issues, err := m.listAllIssues(ctx, repo.Owner, repo.Name, "open")
	if err != nil {
		return nil, fmt.Errorf("listing open dashboard issues: %w", err)
	}

	for _, iss := range issues {
		if isDashboardIssue(iss, title, bot) {
			return &iss, nil
		}
	}
	return nil, nil
}

// Reconcile creates, updates, renames, or closes the dashboard issue.
func (m *Manager) Reconcile(ctx context.Context, repo repo.Identifier, title, bot string, packages []report.PackageFile, existing *Issue) error {
	log := clog.FromContext(ctx)
	hasErrors, hasOpenPRs, hasBlocked := summarize(packages)

	// Fallback pass: If no open issue handle was found during FindOpen, check closed issues.
	if existing == nil {
		closedIssues, err := m.listAllIssues(ctx, repo.Owner, repo.Name, "closed")
		if err == nil {
			for i := range closedIssues {
				iss := closedIssues[i]
				if isDashboardIssue(iss, title, bot) {
					if existing == nil || iss.Number > existing.Number {
						existing = &iss
					}
				}
			}
		}
	}

	closed := "closed"

	if m.AutoClose && !hasErrors && !hasOpenPRs && !hasBlocked {
		if existing == nil || existing.State == "closed" {
			return nil
		}
		return m.Client.EditIssue(ctx, repo.Owner, repo.Name, existing.Number, nil, nil, &closed)
	}

	if existing == nil && !hasErrors && !hasOpenPRs && !hasBlocked {
		return nil
	}

	freshBody := renderBody(packages) + "\n\n" + DashboardMarker

	var titlePtr *string
	if existing != nil && existing.Title != title {
		titlePtr = &title
	}

	startBody := ""
	if existing != nil {
		startBody = existing.Body
	}

	if existing != nil && existing.State == "open" && freshBody == startBody && titlePtr == nil {
		log.Debug("no changes to dependency dashboard issue needed")
		return nil
	}

	if existing != nil {
		freshBody = preserveMidRunChecks(freshBody, existing.Body, startBody)
	}

	if existing == nil {
		return m.Client.CreateIssue(ctx, repo.Owner, repo.Name, title, freshBody)
	}

	var reopen *string
	if existing.State == "closed" {
		open := "open"
		reopen = &open
	}

	return m.Client.EditIssue(ctx, repo.Owner, repo.Name, existing.Number, titlePtr, &freshBody, reopen)
}
