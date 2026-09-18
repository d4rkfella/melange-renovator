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

// IssueClient interface with pagination support.
type IssueClient interface {
	ListIssues(ctx context.Context, owner, repo, state string, page int) ([]Issue, error)
	CreateIssue(ctx context.Context, owner, repo, title, body string) error
	EditIssue(ctx context.Context, owner, repo string, number int, body, state *string) error
}

// Manager implements app.DashboardManager.
type Manager struct {
	Client    IssueClient
	AutoClose bool // currently always false in production — see NewManager
}

// NewManager builds a Manager with the standard dashboard issue title.
// AutoClose defaults to false: the original tool always called this with
// autoclose=false, so a dashboard issue is currently never auto-closed —
// only ever updated or left as-is. Set it explicitly if that should change.
func NewManager(client IssueClient) *Manager {
	return &Manager{Client: client}
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

// listAllIssues pages through GitHub API results (100 per page) to prevent missing issues.
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

func (m *Manager) Read(ctx context.Context, repo repo.Identifier, title, bot string) (Actions, string, error) {
	issues, err := m.listAllIssues(ctx, repo.Owner, repo.Name, "open")
	if err != nil {
		return Actions{}, "", fmt.Errorf("listing open dashboard issues: %w", err)
	}

	for _, iss := range issues {
		if isDashboardIssue(iss, title, bot) {
			return parseDashboardBody(iss.Body), iss.Body, nil
		}
	}
	return Actions{}, "", nil
}

func (m *Manager) Reconcile(ctx context.Context, repo repo.Identifier, title, bot string, packages []report.PackageFile, startBody string) error {
	log := clog.FromContext(ctx)
	hasErrors, hasOpenPRs, hasBlocked := summarize(packages)

	all, err := m.listAllIssues(ctx, repo.Owner, repo.Name, "all")
	if err != nil {
		return fmt.Errorf("listing all issues: %w", err)
	}

	var matching []Issue
	for _, iss := range all {
		if isDashboardIssue(iss, title, bot) {
			matching = append(matching, iss)
		}
	}

	closed := "closed"
	var existing *Issue

	// If multiple open dashboard issues exist (e.g. created by old un-paginated bug), keep 1 open and close duplicate(s).
	for i := range matching {
		iss := matching[i]
		if iss.State != "open" {
			continue
		}
		if existing == nil {
			existing = &iss
			continue
		}
		if err := m.Client.EditIssue(ctx, repo.Owner, repo.Name, iss.Number, nil, &closed); err != nil {
			log.Warn("failed to close duplicate dashboard issue", "number", iss.Number, "error", err)
		}
	}

	if existing == nil {
		for i := range matching {
			iss := matching[i]
			if existing == nil || iss.Number > existing.Number {
				existing = &iss
			}
		}
	}

	if m.AutoClose && !hasErrors && !hasOpenPRs && !hasBlocked {
		if existing == nil || existing.State == "closed" {
			return nil
		}
		return m.Client.EditIssue(ctx, repo.Owner, repo.Name, existing.Number, nil, &closed)
	}

	if existing == nil && !hasErrors && !hasOpenPRs && !hasBlocked {
		return nil
	}

	// Always append marker to ensure continuous recognition even if issue title changes
	freshBody := renderBody(packages) + "\n\n" + DashboardMarker

	if existing != nil && existing.State == "open" && freshBody == startBody {
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
	return m.Client.EditIssue(ctx, repo.Owner, repo.Name, existing.Number, &freshBody, reopen)
}
