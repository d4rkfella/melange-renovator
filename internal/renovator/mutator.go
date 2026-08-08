package renovator

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
)

type mutator interface {
	CommitFile(ctx context.Context, owner, repo, branch, parentSHA string, branchExists bool, path string, content []byte, message string) (sha string, err error)
	CreatePullRequest(ctx context.Context, owner, repo, head, base, title, body string) (*github.PullRequest, error)
	EditPullRequest(ctx context.Context, owner, repo string, number int, edit *github.PullRequest) error
	AddLabels(ctx context.Context, owner, repo string, number int, labels []string) error
	CreateIssueComment(ctx context.Context, owner, repo string, number int, body string) error
	DeleteRef(ctx context.Context, owner, repo, ref string) error
	CreateIssue(ctx context.Context, owner, repo, title, body string) error
	EditIssue(ctx context.Context, owner, repo string, number int, edit *github.IssueRequest) error
	SaveState(ctx context.Context, s3Client *s3.Client, bucket, key string, state packageState) error
}

type liveMutator struct{ gh *github.Client }

func newLiveMutator(gh *github.Client) *liveMutator { return &liveMutator{gh: gh} }

func (m *liveMutator) CommitFile(ctx context.Context, owner, repo, branch, parentSHA string, branchExists bool, path string, content []byte, message string) (string, error) {
	log := clog.FromContext(ctx)
	parentCommit, _, err := m.gh.Git.GetCommit(ctx, owner, repo, parentSHA)
	if err != nil {
		return "", fmt.Errorf("getting parent commit %s: %w", parentSHA, err)
	}
	baseTreeSHA := parentCommit.GetTree().GetSHA()

	newTree, response, err := m.gh.Git.CreateTree(ctx, owner, repo, baseTreeSHA, []*github.TreeEntry{
		{
			Path:    new(path),
			Mode:    new("100644"),
			Type:    new("blob"),
			Content: new(string(content)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating new commit tree: %w", err)
	}
	log.Debug("Successfully created new commit tree", "tree_sha", newTree.GetSHA(), "response_status", response.Status)

	newCommit, _, err := m.gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: new(message),
		Tree:    &github.Tree{SHA: newTree.SHA},
		Parents: []*github.Commit{{SHA: new(parentSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}

	if !branchExists {
		_, _, err := m.gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
			Ref: "refs/heads/" + branch,
			SHA: newCommit.GetSHA(),
		})
		if err != nil && !isRefAlreadyExistsErr(err) {
			return "", fmt.Errorf("creating branch %s: %w", branch, err)
		}
		return newCommit.GetSHA(), nil
	}

	_, _, err = m.gh.Git.UpdateRef(ctx, owner, repo, "refs/heads/"+branch, github.UpdateRef{
		SHA:   newCommit.GetSHA(),
		Force: new(true),
	})
	if err != nil {
		return "", fmt.Errorf("updating branch %s: %w", branch, err)
	}
	return newCommit.GetSHA(), nil
}

func (m *liveMutator) CreatePullRequest(ctx context.Context, owner, repo, head, base, title, body string) (*github.PullRequest, error) {
	var newPR *github.PullRequest
	err := withRetry(ctx, 3, func() error {
		var e error
		newPR, _, e = m.gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
			Title: new(title),
			Body:  new(body),
			Head:  new(head),
			Base:  new(base),
		})
		return e
	})
	return newPR, err
}

func (m *liveMutator) EditPullRequest(ctx context.Context, owner, repo string, number int, edit *github.PullRequest) error {
	_, _, err := m.gh.PullRequests.Edit(ctx, owner, repo, number, edit)
	return err
}

func (m *liveMutator) AddLabels(ctx context.Context, owner, repo string, number int, labels []string) error {
	_, _, err := m.gh.Issues.AddLabelsToIssue(ctx, owner, repo, number, labels)
	return err
}

func (m *liveMutator) CreateIssueComment(ctx context.Context, owner, repo string, number int, body string) error {
	_, _, err := m.gh.Issues.CreateComment(ctx, owner, repo, number, &github.IssueComment{Body: github.Ptr(body)})
	return err
}

func (m *liveMutator) DeleteRef(ctx context.Context, owner, repo, ref string) error {
	_, err := m.gh.Git.DeleteRef(ctx, owner, repo, ref)
	return err
}

func (m *liveMutator) CreateIssue(ctx context.Context, owner, repo, title, body string) error {
	_, _, err := m.gh.Issues.Create(ctx, owner, repo, &github.IssueRequest{
		Title: github.Ptr(title),
		Body:  github.Ptr(body),
	})
	return err
}

func (m *liveMutator) EditIssue(ctx context.Context, owner, repo string, number int, edit *github.IssueRequest) error {
	_, _, err := m.gh.Issues.Edit(ctx, owner, repo, number, edit)
	return err
}

func (m *liveMutator) SaveState(ctx context.Context, s3Client *s3.Client, bucket, key string, state packageState) error {
	return savePackageState(ctx, s3Client, bucket, key, state)
}

type dryRunMutator struct{}

func newDryRunMutator() *dryRunMutator { return &dryRunMutator{} }

func (m *dryRunMutator) CommitFile(ctx context.Context, owner, repo, branch, parentSHA string, branchExists bool, path string, content []byte, message string) (string, error) {
	clog.FromContext(ctx).Info("DRY RUN: would commit file",
		"repo", owner+"/"+repo, "branch", branch, "path", path, "message", message)
	return "dry-run-sha", nil
}

func (m *dryRunMutator) CreatePullRequest(ctx context.Context, owner, repo, head, base, title, body string) (*github.PullRequest, error) {
	clog.FromContext(ctx).Info("DRY RUN: would create PR",
		"repo", owner+"/"+repo, "head", head, "base", base, "title", title)
	return &github.PullRequest{
		Number:  github.Ptr(0),
		HTMLURL: github.Ptr(fmt.Sprintf("https://github.com/%s/%s/pull/dry-run-%s", owner, repo, head)),
	}, nil
}

func (m *dryRunMutator) EditPullRequest(ctx context.Context, owner, repo string, number int, edit *github.PullRequest) error {
	clog.FromContext(ctx).Info("DRY RUN: would edit PR", "repo", owner+"/"+repo, "pr", number)
	return nil
}

func (m *dryRunMutator) AddLabels(ctx context.Context, owner, repo string, number int, labels []string) error {
	clog.FromContext(ctx).Info("DRY RUN: would add labels", "repo", owner+"/"+repo, "pr", number, "labels", labels)
	return nil
}

func (m *dryRunMutator) CreateIssueComment(ctx context.Context, owner, repo string, number int, body string) error {
	clog.FromContext(ctx).Info("DRY RUN: would comment", "repo", owner+"/"+repo, "number", number, "body_preview", truncateString(body, 200))
	return nil
}

func (m *dryRunMutator) DeleteRef(ctx context.Context, owner, repo, ref string) error {
	clog.FromContext(ctx).Info("DRY RUN: would delete ref", "repo", owner+"/"+repo, "ref", ref)
	return nil
}

func (m *dryRunMutator) CreateIssue(ctx context.Context, owner, repo, title, body string) error {
	clog.FromContext(ctx).Info("DRY RUN: would create issue", "repo", owner+"/"+repo, "title", title, "body_preview", truncateString(body, 200))
	return nil
}

func (m *dryRunMutator) EditIssue(ctx context.Context, owner, repo string, number int, edit *github.IssueRequest) error {
	clog.FromContext(ctx).Info("DRY RUN: would edit issue", "repo", owner+"/"+repo, "number", number)
	return nil
}

func (m *dryRunMutator) SaveState(ctx context.Context, s3Client *s3.Client, bucket, key string, state packageState) error {
	clog.FromContext(ctx).Info("DRY RUN: would save package state to S3", "bucket", bucket, "key", key)
	return nil
}
