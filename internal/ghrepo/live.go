package ghrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v81/github"
)

// GitHubAPI is the *github.Client surface liveClient needs. Defining it as
// an interface (rather than depending on *github.Client directly) is what
// lets tests construct a liveClient against a fake transport if ever
// needed, without pulling in the real HTTP stack.
type GitHubAPI = *github.Client

type liveClient struct {
	gh    GitHubAPI
	owner string
	repo  string
}

func fromGHPullRequest(pr *github.PullRequest) *PullRequest {
	if pr == nil {
		return nil
	}
	labels := make([]string, 0, len(pr.Labels))
	for _, l := range pr.Labels {
		labels = append(labels, l.GetName())
	}
	var mergedAt *time.Time
	if pr.MergedAt != nil {
		t := pr.MergedAt.Time
		mergedAt = &t
	}
	return &PullRequest{
		Number:         pr.GetNumber(),
		HTMLURL:        pr.GetHTMLURL(),
		Title:          pr.GetTitle(),
		Body:           pr.GetBody(),
		State:          pr.GetState(),
		BaseRef:        pr.GetBase().GetRef(),
		Mergeable:      pr.Mergeable,
		MergeableState: pr.GetMergeableState(),
		MergedAt:       mergedAt,
		Labels:         labels,
	}
}

func (c *liveClient) DefaultBranch(ctx context.Context) (string, error) {
	var branch string
	err := withRetry(ctx, 3, func() error {
		info, _, e := c.gh.Repositories.Get(ctx, c.owner, c.repo)
		if e != nil {
			return e
		}
		branch = info.GetDefaultBranch()
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("getting repository: %w", err)
	}
	return branch, nil
}

func (c *liveClient) BranchExists(ctx context.Context, branch string) (exists bool, err error) {
	err = withRetry(ctx, 3, func() error {
		_, resp, e := c.gh.Repositories.GetBranch(ctx, c.owner, c.repo, branch, 0)
		exists = e == nil
		if !exists && (resp == nil || resp.StatusCode != 404) {
			return e
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("checking branch existence: %w", err)
	}
	return exists, nil
}

func (c *liveClient) FindOpenPR(ctx context.Context, branch string) (*PullRequest, error) {
	var prs []*github.PullRequest
	err := withRetry(ctx, 3, func() error {
		var e error
		prs, _, e = c.gh.PullRequests.List(ctx, c.owner, c.repo, &github.PullRequestListOptions{
			State: "open",
			Head:  fmt.Sprintf("%s:%s", c.owner, branch),
		})
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("checking for existing branch PRs: %w", err)
	}
	if len(prs) == 0 {
		return nil, nil
	}
	return fromGHPullRequest(prs[0]), nil
}

func (c *liveClient) FindClosedPR(ctx context.Context, branch string) (*PullRequest, error) {
	prs, _, err := c.gh.PullRequests.List(ctx, c.owner, c.repo, &github.PullRequestListOptions{
		State:       "closed",
		Head:        fmt.Sprintf("%s:%s", c.owner, branch),
		ListOptions: github.ListOptions{PerPage: 5},
	})
	if err != nil {
		return nil, fmt.Errorf("listing closed PRs for branch: %w", err)
	}
	if len(prs) == 0 {
		return nil, nil
	}

	candidate := prs[0]
	pr := fromGHPullRequest(candidate)
	if !pr.hasLabel(automationLabel) || candidate.MergedAt != nil {
		return nil, nil
	}
	return pr, nil
}

func (c *liveClient) ListOpenPRsWithTitlePrefix(ctx context.Context, prefix string) ([]*PullRequest, error) {
	var all []*github.PullRequest
	err := withRetry(ctx, 3, func() error {
		var e error
		all, _, e = c.gh.PullRequests.List(ctx, c.owner, c.repo, &github.PullRequestListOptions{State: "open"})
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("listing all open PRs: %w", err)
	}

	var out []*PullRequest
	for _, pr := range all {
		if !strings.HasPrefix(pr.GetTitle(), prefix) {
			continue
		}
		mapped := fromGHPullRequest(pr)
		if !mapped.hasLabel(automationLabel) {
			continue
		}
		out = append(out, mapped)
	}
	return out, nil
}

func (c *liveClient) FileContent(ctx context.Context, path, ref string) (string, error) {
	var file *github.RepositoryContent
	err := withRetry(ctx, 3, func() error {
		var e error
		file, _, _, e = c.gh.Repositories.GetContents(ctx, c.owner, c.repo, path, &github.RepositoryContentGetOptions{Ref: ref})
		return e
	})
	if err != nil {
		return "", err
	}
	return file.GetContent()
}

func (c *liveClient) BranchTipSHA(ctx context.Context, branch string) (string, error) {
	var sha string
	err := withRetry(ctx, 3, func() error {
		ref, _, e := c.gh.Git.GetRef(ctx, c.owner, c.repo, "heads/"+branch)
		if e != nil {
			return e
		}
		sha = ref.GetObject().GetSHA()
		return nil
	})
	return sha, err
}

func (c *liveClient) CompareCommits(ctx context.Context, base, head string) (*Comparison, error) {
	comp, _, err := c.gh.Repositories.CompareCommits(ctx, c.owner, c.repo, base, head, nil)
	if err != nil {
		return nil, fmt.Errorf("comparing %s against %s: %w", head, base, err)
	}
	commits := make([]Commit, len(comp.Commits))
	for i, cm := range comp.Commits {
		commits[i] = Commit{
			SHA:            cm.GetSHA(),
			AuthorLogin:    cm.GetAuthor().GetLogin(),
			AuthorEmail:    cm.GetCommit().GetAuthor().GetEmail(),
			CommitterEmail: cm.GetCommit().GetCommitter().GetEmail(),
		}
	}
	return &Comparison{BehindBy: comp.GetBehindBy(), Commits: commits}, nil
}

func (c *liveClient) RequiresUpToDateBranch(ctx context.Context, branch string) (bool, error) {
	protection, _, err := c.gh.Repositories.GetBranchProtection(ctx, c.owner, c.repo, branch)
	if err != nil {
		if _, ok := errors.AsType[*github.ErrorResponse](err); ok {
			return false, nil // no branch protection configured — not an error
		}
		return false, err
	}
	return protection.RequiredStatusChecks != nil && protection.RequiredStatusChecks.Strict, nil
}

func (c *liveClient) CommitFile(ctx context.Context, branch, parentSHA string, branchExists bool, path string, content []byte, message string) (string, error) {
	parentCommit, _, err := c.gh.Git.GetCommit(ctx, c.owner, c.repo, parentSHA)
	if err != nil {
		return "", fmt.Errorf("getting parent commit %s: %w", parentSHA, err)
	}
	baseTreeSHA := parentCommit.GetTree().GetSHA()

	newTree, _, err := c.gh.Git.CreateTree(ctx, c.owner, c.repo, baseTreeSHA, []*github.TreeEntry{
		{
			Path:    new(path),
			Mode:    new("100644"),
			Type:    new("blob"),
			Content: new(string(content)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}

	newCommit, _, err := c.gh.Git.CreateCommit(ctx, c.owner, c.repo, github.Commit{
		Message: new(message),
		Tree:    &github.Tree{SHA: newTree.SHA},
		Parents: []*github.Commit{{SHA: new(parentSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}

	if !branchExists {
		_, _, err := c.gh.Git.CreateRef(ctx, c.owner, c.repo, github.CreateRef{
			Ref: "refs/heads/" + branch,
			SHA: newCommit.GetSHA(),
		})
		if err != nil && !isRefAlreadyExistsErr(err) {
			return "", fmt.Errorf("creating branch %s: %w", branch, err)
		}
		return newCommit.GetSHA(), nil
	}

	_, _, err = c.gh.Git.UpdateRef(ctx, c.owner, c.repo, "refs/heads/"+branch, github.UpdateRef{
		SHA:   newCommit.GetSHA(),
		Force: new(true),
	})
	if err != nil {
		return "", fmt.Errorf("updating branch %s: %w", branch, err)
	}
	return newCommit.GetSHA(), nil
}

func (c *liveClient) CreatePullRequest(ctx context.Context, head, base, title, body string) (*PullRequest, error) {
	var newPR *github.PullRequest
	err := withRetry(ctx, 3, func() error {
		var e error
		newPR, _, e = c.gh.PullRequests.Create(ctx, c.owner, c.repo, &github.NewPullRequest{
			Title: new(title), Body: new(body), Head: new(head), Base: new(base),
		})
		return e
	})
	if err != nil {
		return nil, err
	}
	return fromGHPullRequest(newPR), nil
}

func (c *liveClient) ClosePullRequest(ctx context.Context, number int) error {
	_, _, err := c.gh.PullRequests.Edit(ctx, c.owner, c.repo, number, &github.PullRequest{State: github.Ptr("closed")})
	return err
}

func (c *liveClient) ReopenPullRequest(ctx context.Context, number int) error {
	_, _, err := c.gh.PullRequests.Edit(ctx, c.owner, c.repo, number, &github.PullRequest{State: github.Ptr("open")})
	return err
}

func (c *liveClient) SetPullRequestBody(ctx context.Context, number int, body string) error {
	_, _, err := c.gh.PullRequests.Edit(ctx, c.owner, c.repo, number, &github.PullRequest{Body: github.Ptr(body)})
	return err
}

func (c *liveClient) RetargetPullRequestBase(ctx context.Context, number int, base string) error {
	_, _, err := c.gh.PullRequests.Edit(ctx, c.owner, c.repo, number, &github.PullRequest{
		Base: &github.PullRequestBranch{Ref: github.Ptr(base)},
	})
	return err
}

func (c *liveClient) AddLabels(ctx context.Context, number int, labels []string) error {
	_, _, err := c.gh.Issues.AddLabelsToIssue(ctx, c.owner, c.repo, number, labels)
	return err
}

func (c *liveClient) CreateIssueComment(ctx context.Context, number int, body string) error {
	_, _, err := c.gh.Issues.CreateComment(ctx, c.owner, c.repo, number, &github.IssueComment{Body: github.Ptr(body)})
	return err
}

func (c *liveClient) DeleteRef(ctx context.Context, ref string) error {
	_, err := c.gh.Git.DeleteRef(ctx, c.owner, c.repo, ref)
	return err
}
