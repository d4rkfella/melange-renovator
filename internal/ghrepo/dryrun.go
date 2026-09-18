package ghrepo

import (
	"context"
	"fmt"

	"github.com/chainguard-dev/clog"
)

// dryRunClient reads through to a real Reader — dry-run still needs to see
// actual repository state to make sound decisions — but logs instead of
// calling the API for every write.
type dryRunClient struct {
	Reader
	owner, repo string
}

func (c *dryRunClient) fullName() string { return c.owner + "/" + c.repo }

func (c *dryRunClient) CommitFile(ctx context.Context, branch, _ string, _ bool, path string, _ []byte, message string) (string, error) {
	clog.FromContext(ctx).Info("DRY RUN: would commit file", "repo", c.fullName(), "branch", branch, "path", path, "message", message)
	return "dry-run-sha", nil
}

func (c *dryRunClient) CreatePullRequest(ctx context.Context, head, base, title, _ string) (*PullRequest, error) {
	clog.FromContext(ctx).Info("DRY RUN: would create PR", "repo", c.fullName(), "head", head, "base", base, "title", title)
	return &PullRequest{
		Number:  0,
		HTMLURL: fmt.Sprintf("https://github.com/%s/pull/dry-run-%s", c.fullName(), head),
	}, nil
}

func (c *dryRunClient) ClosePullRequest(ctx context.Context, number int) error {
	clog.FromContext(ctx).Info("DRY RUN: would close PR", "repo", c.fullName(), "pr", number)
	return nil
}

func (c *dryRunClient) ReopenPullRequest(ctx context.Context, number int) error {
	clog.FromContext(ctx).Info("DRY RUN: would reopen PR", "repo", c.fullName(), "pr", number)
	return nil
}

func (c *dryRunClient) SetPullRequestBody(ctx context.Context, number int, _ string) error {
	clog.FromContext(ctx).Info("DRY RUN: would edit PR body", "repo", c.fullName(), "pr", number)
	return nil
}

func (c *dryRunClient) RetargetPullRequestBase(ctx context.Context, number int, base string) error {
	clog.FromContext(ctx).Info("DRY RUN: would retarget PR base", "repo", c.fullName(), "pr", number, "base", base)
	return nil
}

func (c *dryRunClient) AddLabels(ctx context.Context, number int, labels []string) error {
	clog.FromContext(ctx).Info("DRY RUN: would add labels", "repo", c.fullName(), "pr", number, "labels", labels)
	return nil
}

func (c *dryRunClient) CreateIssueComment(ctx context.Context, number int, body string) error {
	clog.FromContext(ctx).Info("DRY RUN: would comment", "repo", c.fullName(), "number", number, "body_preview", truncate(body, 200))
	return nil
}

func (c *dryRunClient) DeleteRef(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Info("DRY RUN: would delete ref", "repo", c.fullName(), "ref", ref)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... (truncated)"
}
