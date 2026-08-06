package renovator

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v81/github"
)

func listInstallationRepos(ctx context.Context, gh *github.Client) ([]*github.Repository, error) {
	var all []*github.Repository
	opts := &github.ListOptions{PerPage: 100}

	for {
		result, resp, err := gh.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("listing installation repositories: %w", err)
		}
		all = append(all, result.Repositories...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return all, nil
}

func filterRepos(repos []*github.Repository, patterns []string) []*github.Repository {
	if len(patterns) == 0 {
		return repos
	}

	var matched []*github.Repository
	for _, r := range repos {
		fullName := r.GetFullName()
		for _, p := range patterns {
			if ok, _ := path.Match(p, fullName); ok {
				matched = append(matched, r)
				break
			}
		}
	}
	return matched
}

func repoLocalDir(baseDir string, repo *github.Repository) string {
	return filepath.Join(baseDir, "repos", "github", repo.GetOwner().GetLogin(), repo.GetName())
}

func prepareRepo(ctx context.Context, repo *github.Repository, token, baseDir string) (localDir string, err error) {
	log := clog.FromContext(ctx).With(
		"repository", repo.GetFullName(),
	)

	localDir = repoLocalDir(baseDir, repo)
	auth := &githttp.BasicAuth{
		Username: "x-access-token",
		Password: token,
	}
	defaultBranch := repo.GetDefaultBranch()

	log.Debug(fmt.Sprintf("Initializing git repository into %s", localDir))

	if r, openErr := git.PlainOpen(localDir); openErr == nil {
		log.Debug("Found existing repository")

		start := time.Now()

		refreshErr := refreshExistingClone(ctx, r, auth, defaultBranch)
		if refreshErr == nil {
			log.Debug("Repository synchronized",
				"durationMs", time.Since(start).Milliseconds(),
			)

			logRepositoryState(log, r)
			return localDir, nil
		}

		log.Debug("Failed to refresh repository, removing local clone",
			"error", refreshErr,
		)

		_ = os.RemoveAll(localDir)
	} else {
		log.Debug("Repository does not exist, creating new shallow clone")
	}

	if err := os.MkdirAll(filepath.Dir(localDir), 0o755); err != nil {
		return "", fmt.Errorf("creating repo cache parent dir: %w", err)
	}

	start := time.Now()

	r, err := git.PlainCloneContext(ctx, localDir, false, &git.CloneOptions{
		URL:          repo.GetCloneURL(),
		Auth:         auth,
		Depth:        1,
		SingleBranch: true,
	})

	if err != nil {
		return "", fmt.Errorf("cloning %s: %w", repo.GetFullName(), err)
	}

	log.Debug("git clone completed",
		"durationMs", time.Since(start).Milliseconds(),
	)

	logRepositoryState(log, r)

	return localDir, nil
}

func refreshExistingClone(ctx context.Context, r *git.Repository, auth *githttp.BasicAuth, defaultBranch string) error {
	log := clog.FromContext(ctx)

	refSpec := gitconfig.RefSpec(fmt.Sprintf(
		"+refs/heads/%s:refs/remotes/origin/%s",
		defaultBranch,
		defaultBranch,
	))

	log.Debug(fmt.Sprintf("Fetching latest changes from origin/%s", defaultBranch))

	start := time.Now()

	err := r.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		RefSpecs:   []gitconfig.RefSpec{refSpec},
		Auth:       auth,
		Depth:      1,
		Force:      true,
	})

	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("fetching latest %s: %w", defaultBranch, err)
	}

	log.Debug("git fetch completed",
		"durationMs", time.Since(start).Milliseconds(),
	)

	remoteRef, err := r.Reference(plumbing.NewRemoteReferenceName("origin", defaultBranch), true)
	if err != nil {
		return fmt.Errorf("resolving fetched ref: %w", err)
	}

	log.Debug(fmt.Sprintf("Resetting worktree to origin/%s", defaultBranch))

	wt, err := r.Worktree()
	if err != nil {
		return fmt.Errorf("getting worktree: %w", err)
	}

	if err := wt.Reset(&git.ResetOptions{
		Commit: remoteRef.Hash(),
		Mode:   git.HardReset,
	}); err != nil {
		return fmt.Errorf("resetting worktree: %w", err)
	}

	log.Debug("Cleaning worktree")

	if err := wt.Clean(&git.CleanOptions{
		Dir: true,
	}); err != nil {
		return fmt.Errorf("cleaning worktree: %w", err)
	}

	return nil
}

func logRepositoryState(log *clog.Logger, r *git.Repository) {
	head, err := r.Head()
	if err != nil {
		return
	}

	commit, err := r.CommitObject(head.Hash())
	if err != nil {
		return
	}

	log.Debug("latest repository commit",
		"latestCommit", map[string]any{
			"hash":         commit.Hash.String(),
			"date":         commit.Author.When,
			"message":      strings.TrimSpace(commit.Message),
			"author_name":  commit.Author.Name,
			"author_email": commit.Author.Email,
		},
	)

	log.Debug(fmt.Sprintf("Current branch SHA: %s", head.Hash()))
}
