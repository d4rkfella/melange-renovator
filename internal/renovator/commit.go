package renovator

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
)

var errBranchModifiedByHuman = errors.New("branch has commits from someone other than this tool and will not be automatically rebuilt; resolve conflicts manually")

func isRefAlreadyExistsErr(err error) bool {
	if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok {
		for _, e := range ghErr.Errors {
			if e.Code == "already_exists" {
				return true
			}
		}
	}
	return false
}

func hasUnmanagedCommitsOnBranch(ctx context.Context, gh *github.Client, owner, repo, defaultBranch, prBranch string) (bool, error) {
	self, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		return false, fmt.Errorf("resolving authenticated identity: %w", err)
	}
	selfLogin := self.GetLogin()

	comparison, _, err := gh.Repositories.CompareCommits(ctx, owner, repo, prBranch, defaultBranch, nil)
	if err != nil {
		return false, fmt.Errorf("comparing %s...%s: %w", defaultBranch, prBranch, err)
	}

	for _, c := range comparison.Commits {
		if login := c.GetAuthor().GetLogin(); login != "" && login != selfLogin {
			return true, nil
		}
		if login := c.GetCommitter().GetLogin(); login != "" && login != selfLogin {
			return true, nil
		}
	}
	return false, nil
}

func commitFileOnBranch(
	ctx context.Context,
	gh *github.Client,
	owner, repo, prBranch, parentSHA string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
) (newCommitSHA string, err error) {
	parentCommit, _, err := gh.Git.GetCommit(ctx, owner, repo, parentSHA)
	if err != nil {
		return "", fmt.Errorf("getting parent commit %s: %w", parentSHA, err)
	}
	baseTreeSHA := parentCommit.GetTree().GetSHA()

	newTree, _, err := gh.Git.CreateTree(ctx, owner, repo, baseTreeSHA, []*github.TreeEntry{
		{
			Path:    github.Ptr(relPath),
			Mode:    github.Ptr("100644"),
			Type:    github.Ptr("blob"),
			Content: github.Ptr(string(content)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}

	newCommit, _, err := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: github.Ptr(commitMessage),
		Tree:    &github.Tree{SHA: newTree.SHA},
		Parents: []*github.Commit{{SHA: github.Ptr(parentSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}

	if err := updateBranchRef(ctx, gh, owner, repo, prBranch, newCommit.GetSHA(), branchExists); err != nil {
		return "", err
	}

	return newCommit.GetSHA(), nil
}

func updateBranchRef(ctx context.Context, gh *github.Client, owner, repo, branch, newSHA string, branchExists bool) error {
	if !branchExists {
		_, _, err := gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
			Ref: "refs/heads/" + branch,
			SHA: newSHA,
		})
		if err != nil && !isRefAlreadyExistsErr(err) {
			return fmt.Errorf("creating branch %s: %w", branch, err)
		}
		return nil
	}

	_, _, err := gh.Git.UpdateRef(ctx, owner, repo, "refs/heads/"+branch, github.UpdateRef{
		SHA:   newSHA,
		Force: github.Ptr(true),
	})
	if err != nil {
		return fmt.Errorf("updating branch %s: %w", branch, err)
	}
	return nil
}

func commitFileWithRetry(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, prBranch string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
) (newCommitSHA string, err error) {
	log := clog.FromContext(ctx)

	if branchExists {
		modified, mErr := hasUnmanagedCommitsOnBranch(ctx, gh, owner, repo, defaultBranch, prBranch)
		if mErr != nil {
			return "", fmt.Errorf("checking branch modification status: %w", mErr)
		}
		if modified {
			log.Warn("branch has commits from someone other than this tool, leaving it untouched",
				"branch", prBranch)
			return "", errBranchModifiedByHuman
		}
	}

	var parentSHA string
	err = withRetry(ctx, 3, func() error {
		ref, _, e := gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
		if e != nil {
			return e
		}
		parentSHA = ref.Object.GetSHA()
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("resolving current tip of %s: %w", defaultBranch, err)
	}

	err = withRetry(ctx, 3, func() error {
		var e error
		newCommitSHA, e = commitFileOnBranch(ctx, gh, owner, repo, prBranch, parentSHA, branchExists, relPath, content, commitMessage)
		return e
	})
	if err != nil {
		log.Debug("commit failed", "branch", prBranch, "error", err)
		return "", err
	}
	return newCommitSHA, nil
}
