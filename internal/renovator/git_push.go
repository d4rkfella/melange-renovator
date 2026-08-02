package renovator

import (
	"context"
	"fmt"
	"strings"
	"time"

	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"

	billymemfs "github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"

	"github.com/chainguard-dev/clog"
)

const nonFastForwardSubstring = "non-fast-forward update"

func isRepositoryChangedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), nonFastForwardSubstring)
}

func gitCommitAuthor() *object.Signature {
	name := "melange-renovator"
	email := "melange-renovator@users.noreply.github.com"
	return &object.Signature{Name: name, Email: email, When: time.Now()}
}

func pushFileToBranch(
	ctx context.Context,
	cloneURL, token, defaultBranch, prBranch string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
) (pushed bool, err error) {
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: token}

	storer := memory.NewStorage()
	fs := billymemfs.New()

	r, err := git.CloneContext(ctx, storer, fs, &git.CloneOptions{
		URL:           cloneURL,
		Auth:          auth,
		Depth:         1,
		SingleBranch:  true,
		ReferenceName: plumbing.NewBranchReferenceName(defaultBranch),
	})
	if err != nil {
		return false, fmt.Errorf("cloning %s: %w", cloneURL, err)
	}

	w, err := r.Worktree()
	if err != nil {
		return false, fmt.Errorf("getting worktree: %w", err)
	}

	if branchExists {
		refSpec := gitconfig.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", prBranch, prBranch))
		fetchErr := r.FetchContext(ctx, &git.FetchOptions{
			RemoteName: "origin",
			RefSpecs:   []gitconfig.RefSpec{refSpec},
			Auth:       auth,
			Depth:      1,
		})
		if fetchErr != nil && fetchErr != git.NoErrAlreadyUpToDate {
			return false, fmt.Errorf("fetching existing branch %s: %w", prBranch, fetchErr)
		}

		remoteRef, refErr := r.Reference(plumbing.NewRemoteReferenceName("origin", prBranch), true)
		if refErr != nil {
			return false, fmt.Errorf("resolving fetched branch %s: %w", prBranch, refErr)
		}
		if err := r.Storer.SetReference(plumbing.NewHashReference(
			plumbing.NewBranchReferenceName(prBranch), remoteRef.Hash())); err != nil {
			return false, fmt.Errorf("creating local ref for %s: %w", prBranch, err)
		}
	} else {
		headRef, headErr := r.Head()
		if headErr != nil {
			return false, fmt.Errorf("resolving HEAD: %w", headErr)
		}
		if err := r.Storer.SetReference(plumbing.NewHashReference(
			plumbing.NewBranchReferenceName(prBranch), headRef.Hash())); err != nil {
			return false, fmt.Errorf("creating local ref for %s: %w", prBranch, err)
		}
	}

	if err := w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(prBranch),
		Force:  true,
	}); err != nil {
		return false, fmt.Errorf("checking out %s: %w", prBranch, err)
	}

	f, err := fs.Create(relPath)
	if err != nil {
		return false, fmt.Errorf("opening %s in worktree: %w", relPath, err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("writing %s: %w", relPath, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("closing %s: %w", relPath, err)
	}

	if _, err := w.Add(relPath); err != nil {
		return false, fmt.Errorf("staging %s: %w", relPath, err)
	}

	status, err := w.Status()
	if err != nil {
		return false, fmt.Errorf("getting worktree status: %w", err)
	}
	if status.IsClean() {
		return false, nil
	}

	if _, err := w.Commit(commitMessage, &git.CommitOptions{
		Author: gitCommitAuthor(),
	}); err != nil {
		return false, fmt.Errorf("committing: %w", err)
	}

	pushErr := r.PushContext(ctx, &git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		RefSpecs: []gitconfig.RefSpec{
			gitconfig.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", prBranch, prBranch)),
		},
	})
	if pushErr != nil && pushErr != git.NoErrAlreadyUpToDate {
		return false, pushErr
	}

	return true, nil
}

func pushFileWithRetry(
	ctx context.Context,
	cloneURL, token, defaultBranch, prBranch string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
	maxAttempts int,
) (pushed bool, err error) {
	log := clog.FromContext(ctx)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pushed, err = pushFileToBranch(ctx, cloneURL, token, defaultBranch, prBranch, branchExists, relPath, content, commitMessage)
		if err == nil {
			return pushed, nil
		}
		if !isRepositoryChangedErr(err) || attempt == maxAttempts {
			return false, err
		}
		log.Warn("branch changed remotely between clone and push, retrying",
			"attempt", attempt, "branch", prBranch, "error", err)
		branchExists = true
	}
	return false, err
}
