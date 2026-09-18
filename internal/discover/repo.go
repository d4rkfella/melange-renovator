package discover

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/repo"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v81/github"
)

// InstallationLister is the narrow GitHub API surface needed to enumerate
// repositories visible to the current GitHub App installation. Defining it
// here (rather than depending on *github.Client directly) means the
// listing/filtering logic below is testable without a real API call.
type InstallationLister interface {
	ListInstallationRepos(ctx context.Context) ([]InstallationRepo, error)
}

// InstallationRepo is the subset of repository metadata Discoverer needs.
type InstallationRepo struct {
	Owner         string
	Name          string
	CloneURL      string
	DefaultBranch string
}

func (r InstallationRepo) fullName() string { return r.Owner + "/" + r.Name }

// GitHubInstallationLister implements InstallationLister against a real
// *github.Client.
type GitHubInstallationLister struct {
	GH *github.Client
}

func (l GitHubInstallationLister) ListInstallationRepos(ctx context.Context) ([]InstallationRepo, error) {
	var all []InstallationRepo
	opts := &github.ListOptions{PerPage: 100}
	for {
		result, resp, err := l.GH.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("listing installation repositories: %w", err)
		}
		for _, r := range result.Repositories {
			all = append(all, InstallationRepo{
				Owner:         r.GetOwner().GetLogin(),
				Name:          r.GetName(),
				CloneURL:      r.GetCloneURL(),
				DefaultBranch: r.GetDefaultBranch(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// Discoverer implements app.Discoverer: it lists repositories visible to
// the GitHub App installation, filters them by the configured autodiscover
// patterns, and shallow-clones (or refreshes) each one locally.
//
// PrepareLocal must be called with a Repo that was returned by a prior
// ListRepos call on the same Discoverer — it looks up clone metadata from
// that call rather than re-fetching it. app.Runner's control flow already
// guarantees this (it always calls ListRepos once, then PrepareLocal per
// result, sequentially); a Discoverer used outside that flow needs to
// preserve the same order.
type Discoverer struct {
	Lister InstallationLister
	Token  string // git HTTP basic-auth password for cloning
	Filter []string

	mu     sync.Mutex
	byName map[string]InstallationRepo
}

func NewDiscoverer(lister InstallationLister, token string, filter []string) *Discoverer {
	return &Discoverer{Lister: lister, Token: token, Filter: filter, byName: make(map[string]InstallationRepo)}
}

func (d *Discoverer) ListRepos(ctx context.Context) ([]repo.Identifier, error) {
	all, err := d.Lister.ListInstallationRepos(ctx)
	if err != nil {
		return nil, err
	}
	matched := filterRepos(all, d.Filter)

	d.mu.Lock()
	defer d.mu.Unlock()
	repos := make([]repo.Identifier, len(matched))
	for i, r := range matched {
		repos[i] = repo.Identifier{Owner: r.Owner, Name: r.Name}
		d.byName[r.fullName()] = r
	}
	return repos, nil
}

func (d *Discoverer) PrepareLocal(ctx context.Context, repo repo.Identifier, baseDir string) (string, error) {
	d.mu.Lock()
	meta, ok := d.byName[repo.FullName()]
	d.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("PrepareLocal called for %s before ListRepos returned it", repo.FullName())
	}
	return prepareClone(ctx, meta, d.Token, baseDir)
}

func filterRepos(repos []InstallationRepo, patterns []string) []InstallationRepo {
	if len(patterns) == 0 {
		return repos
	}
	var matched []InstallationRepo
	for _, r := range repos {
		full := r.fullName()
		for _, p := range patterns {
			if ok, _ := path.Match(p, full); ok {
				matched = append(matched, r)
				break
			}
		}
	}
	return matched
}

func repoLocalDir(baseDir string, r InstallationRepo) string {
	return filepath.Join(baseDir, "repos", "github", r.Owner, r.Name)
}

func prepareClone(ctx context.Context, r InstallationRepo, token, baseDir string) (string, error) {
	log := clog.FromContext(ctx)

	localDir := repoLocalDir(baseDir, r)
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: token}

	log.Debug("initializing git repository", "dir", localDir)

	if repo, err := git.PlainOpen(localDir); err == nil {
		start := time.Now()
		if refreshErr := refreshExistingClone(ctx, repo, auth, r.DefaultBranch); refreshErr == nil {
			log.Debug("repository synchronized", "duration_ms", time.Since(start).Milliseconds())
			logRepositoryState(log, repo)
			return localDir, nil
		} else {
			log.Debug("failed to refresh repository, removing local clone", "error", refreshErr)
			_ = os.RemoveAll(localDir)
		}
	}

	if err := os.MkdirAll(filepath.Dir(localDir), 0o755); err != nil {
		return "", fmt.Errorf("creating repo cache parent dir: %w", err)
	}

	log.Debug("performing shallow clone")
	start := time.Now()
	repo, err := git.PlainCloneContext(ctx, localDir, false, &git.CloneOptions{
		URL: r.CloneURL, Auth: auth, Depth: 1, SingleBranch: true,
	})
	if err != nil {
		return "", fmt.Errorf("cloning %s: %w", r.fullName(), err)
	}
	log.Debug("git clone completed", "duration_ms", time.Since(start).Milliseconds())
	logRepositoryState(log, repo)
	return localDir, nil
}

func refreshExistingClone(ctx context.Context, r *git.Repository, auth *githttp.BasicAuth, defaultBranch string) error {
	log := clog.FromContext(ctx)
	refSpec := gitconfig.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", defaultBranch, defaultBranch))

	start := time.Now()
	err := r.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin", RefSpecs: []gitconfig.RefSpec{refSpec}, Auth: auth, Depth: 1, Force: true,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("fetching latest %s: %w", defaultBranch, err)
	}
	log.Debug("git fetch completed", "duration_ms", time.Since(start).Milliseconds())

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
	return wt.Clean(&git.CleanOptions{Dir: true})
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
	subject := strings.TrimSpace(commit.Message)
	body := ""
	if parts := strings.SplitN(commit.Message, "\n\n", 2); len(parts) == 2 {
		subject = strings.TrimSpace(parts[0])
		body = strings.TrimSpace(parts[1])
	}

	var refs []string
	if iter, err := r.References(); err == nil {
		_ = iter.ForEach(func(ref *plumbing.Reference) error {
			if ref.Hash() != commit.Hash {
				return nil
			}
			name := ref.Name().Short()
			if ref.Name() == head.Name() {
				name = "HEAD -> " + name
			}
			refs = append(refs, name)
			return nil
		})
	}

	log.Debug("latest repository commit",
		"hash", commit.Hash.String(), "date", commit.Author.When, "message", subject, "body", body,
		"refs", strings.Join(refs, ", "), "author_name", commit.Author.Name, "author_email", commit.Author.Email)
}
