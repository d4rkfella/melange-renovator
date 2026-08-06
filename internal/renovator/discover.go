package renovator

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

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
	localDir = repoLocalDir(baseDir, repo)
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: token}
	defaultBranch := repo.GetDefaultBranch()

	if r, openErr := git.PlainOpen(localDir); openErr == nil {
		if refreshErr := refreshExistingClone(ctx, r, auth, defaultBranch); refreshErr == nil {
			return localDir, nil
		}
		_ = os.RemoveAll(localDir)
	}

	if err := os.MkdirAll(filepath.Dir(localDir), 0o755); err != nil {
		return "", fmt.Errorf("creating repo cache parent dir: %w", err)
	}

	_, err = git.PlainCloneContext(ctx, localDir, false, &git.CloneOptions{
		URL:          repo.GetCloneURL(),
		Auth:         auth,
		Depth:        1,
		SingleBranch: true,
	})
	if err != nil {
		return "", fmt.Errorf("cloning %s: %w", repo.GetFullName(), err)
	}

	return localDir, nil
}

func refreshExistingClone(ctx context.Context, r *git.Repository, auth *githttp.BasicAuth, defaultBranch string) error {
	refSpec := gitconfig.RefSpec(fmt.Sprintf(
		"+refs/heads/%s:refs/remotes/origin/%s", defaultBranch, defaultBranch,
	))

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

	remoteRef, err := r.Reference(plumbing.NewRemoteReferenceName("origin", defaultBranch), true)
	if err != nil {
		return fmt.Errorf("resolving fetched ref: %w", err)
	}

	wt, err := r.Worktree()
	if err != nil {
		return fmt.Errorf("getting worktree: %w", err)
	}

	if err := wt.Reset(&git.ResetOptions{Commit: remoteRef.Hash(), Mode: git.HardReset}); err != nil {
		return fmt.Errorf("resetting worktree: %w", err)
	}

	if err := wt.Clean(&git.CleanOptions{Dir: true}); err != nil {
		return fmt.Errorf("cleaning worktree: %w", err)
	}

	return nil
}
