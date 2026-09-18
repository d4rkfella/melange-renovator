package versioning

import (
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/config"
)

// GitTag is a remote tag name paired with the commit it ultimately points
// at (annotated tags already dereferenced).
type GitTag struct {
	Name string
	SHA  string
}

// GitRemote is the narrow git-remote surface a GitResolver needs. The
// production implementation wraps go-git against an in-memory remote
// (no local clone needed just to list tags); tests can substitute a fake
// with a fixed tag list instead.
type GitRemote interface {
	ListTags(ctx context.Context, url string) ([]GitTag, error)
	ResolveTagCommit(ctx context.Context, url, tag string) (string, error)
}

// GitResolver resolves versions from a raw git remote's tags, per
// config.GitMonitor. RepoURL comes from the package's git-checkout
// pipeline step, not from the monitor config itself.
type GitResolver struct {
	Remote  GitRemote
	RepoURL string
	Monitor *config.GitMonitor
}

func (r GitResolver) Resolve(ctx context.Context, patterns Patterns) (Result, error) {
	if r.RepoURL == "" {
		return Result{}, fmt.Errorf("no git-checkout step found in pipeline")
	}

	tags, err := r.Remote.ListTags(ctx, r.RepoURL)
	if err != nil {
		return Result{}, fmt.Errorf("listing remote refs: %w", err)
	}
	if len(tags) == 0 {
		return Result{}, fmt.Errorf("no tags found in repository %s", r.RepoURL)
	}

	names := make([]string, len(tags))
	for i, t := range tags {
		names[i] = t.Name
	}

	best, stats, err := ResolveBest(ctx, names, r.Monitor, patterns)
	if err != nil {
		return Result{}, err
	}

	sha, err := r.Remote.ResolveTagCommit(ctx, r.RepoURL, best.Upstream)
	if err != nil {
		return Result{}, fmt.Errorf("resolving commit for tag %s: %w", best.Upstream, err)
	}

	return Result{
		Version: best.Transformed, UpstreamTag: best.Upstream, CommitSHA: sha,
		TagsConsidered: stats.Total, TagsSkipped: stats.Skipped,
	}, nil
}

// GitCheckoutRepoURL extracts the repository URL from a package config's
// git-checkout pipeline step, if any.
func GitCheckoutRepoURL(cfg *config.Configuration) string {
	for _, step := range cfg.Pipeline {
		if step.Uses == "git-checkout" {
			if repo := step.With["repository"]; repo != "" {
				return repo
			}
		}
	}
	return ""
}
