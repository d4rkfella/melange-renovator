package dashboard

import (
	"context"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
)

// GitHubIssueClient implements IssueClient against a real *github.Client.
type GitHubIssueClient struct {
	GH *github.Client
}

func (c GitHubIssueClient) ListIssues(ctx context.Context, owner, repo, state string, page int) ([]Issue, error) {
	opts := &github.IssueListByRepoOptions{
		State: state,
		ListOptions: github.ListOptions{
			Page:    page,
			PerPage: 100, // Query maximum allowable page size
		},
	}

	ghIssues, _, err := c.GH.Issues.ListByRepo(ctx, owner, repo, opts)
	if err != nil {
		return nil, err
	}

	out := make([]Issue, 0, len(ghIssues))
	for _, iss := range ghIssues {
		// Ignore Pull Requests returned by GitHub Issues API
		if iss.IsPullRequest() {
			continue
		}

		out = append(out, Issue{
			Number: iss.GetNumber(),
			Title:  iss.GetTitle(),
			Body:   iss.GetBody(),
			State:  iss.GetState(),
			Author: iss.GetUser().GetLogin(),
		})
	}
	return out, nil
}

func (c GitHubIssueClient) CreateIssue(ctx context.Context, owner, repo, title, body string) error {
	_, _, err := c.GH.Issues.Create(ctx, owner, repo, &github.IssueRequest{Title: new(title), Body: new(body)})
	return err
}

func (c GitHubIssueClient) EditIssue(ctx context.Context, owner, repo string, number int, body, state *string) error {
	_, _, err := c.GH.Issues.Edit(ctx, owner, repo, number, &github.IssueRequest{Body: body, State: state})
	return err
}

// DryRunIssueClient reads through to a real IssueClient but logs instead of
// writing, matching the same live-reads/stubbed-writes convention used by
// ghrepo's dry-run Client.
type DryRunIssueClient struct {
	IssueClient
}

func (c DryRunIssueClient) CreateIssue(ctx context.Context, owner, repo, title, _ string) error {
	clog.FromContext(ctx).Info("DRY RUN: would create dashboard issue", "repo", owner+"/"+repo, "title", title)
	return nil
}

func (c DryRunIssueClient) EditIssue(ctx context.Context, owner, repo string, number int, _, _ *string) error {
	clog.FromContext(ctx).Info("DRY RUN: would edit dashboard issue", "repo", owner+"/"+repo, "number", number)
	return nil
}
