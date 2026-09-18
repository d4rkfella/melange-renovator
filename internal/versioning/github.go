package versioning

import (
	"context"
	"fmt"
	"strings"

	"chainguard.dev/melange/pkg/config"
)

// TagCommit pairs a tag name with the commit SHA it ultimately points at
// (annotated tags already dereferenced to the underlying commit).
type TagCommit struct {
	Name string
	SHA  string
}

// GitHubTagSource is the narrow slice of the GitHub API a GitHubResolver
// needs. Its concrete implementation lives in internal/ghrepo and wraps
// go-github; defining the interface here means versioning has no
// import-time dependency on ghrepo or go-github at all.
type GitHubTagSource interface {
	ListTags(ctx context.Context, owner, repo string) ([]TagCommit, error)
	ListReleaseTags(ctx context.Context, owner, repo string, includePrerelease bool) ([]string, error)
	ResolveTagCommit(ctx context.Context, owner, repo, tag string) (string, error)
}

// GitHubResolver resolves versions from a GitHub repository's tags or
// releases, per config.GitHubMonitor.
type GitHubResolver struct {
	Source               GitHubTagSource
	Monitor              *config.GitHubMonitor
	EnablePreReleaseTags bool // only consulted when Monitor.UseTags is false
}

func (r GitHubResolver) Resolve(ctx context.Context, patterns Patterns) (Result, error) {
	owner, repo, err := splitIdentifier(r.Monitor.Identifier)
	if err != nil {
		return Result{}, err
	}

	if r.Monitor.UseTags {
		return r.resolveFromTags(ctx, owner, repo, patterns)
	}
	return r.resolveFromReleases(ctx, owner, repo, patterns)
}

func (r GitHubResolver) resolveFromTags(ctx context.Context, owner, repo string, patterns Patterns) (Result, error) {
	tags, err := r.Source.ListTags(ctx, owner, repo)
	if err != nil {
		return Result{}, fmt.Errorf("listing tags: %w", err)
	}
	if len(tags) == 0 {
		return Result{}, fmt.Errorf("no tags found for GitHub repository %s/%s", owner, repo)
	}

	names := make([]string, len(tags))
	for i, t := range tags {
		names[i] = t.Name
	}

	best, stats, err := ResolveBest(ctx, names, r.Monitor, patterns)
	if err != nil {
		return Result{}, fmt.Errorf("no valid tags found for %s/%s: %w", owner, repo, err)
	}

	for _, t := range tags {
		if t.Name == best.Upstream {
			return Result{
				Version: best.Transformed, UpstreamTag: best.Upstream, CommitSHA: t.SHA,
				TagsConsidered: stats.Total, TagsSkipped: stats.Skipped,
			}, nil
		}
	}
	return Result{}, fmt.Errorf("failed to resolve SHA for tag %s", best.Upstream)
}

func (r GitHubResolver) resolveFromReleases(ctx context.Context, owner, repo string, patterns Patterns) (Result, error) {
	tagNames, err := r.Source.ListReleaseTags(ctx, owner, repo, r.EnablePreReleaseTags)
	if err != nil {
		return Result{}, fmt.Errorf("listing releases: %w", err)
	}
	if len(tagNames) == 0 {
		return Result{}, fmt.Errorf("no releases found for GitHub repository %s/%s", owner, repo)
	}

	best, stats, err := ResolveBest(ctx, tagNames, r.Monitor, patterns)
	if err != nil {
		return Result{}, fmt.Errorf("no valid versions found for %s/%s: %w", owner, repo, err)
	}

	sha, err := r.Source.ResolveTagCommit(ctx, owner, repo, best.Upstream)
	if err != nil {
		return Result{}, fmt.Errorf("resolving commit for tag %s: %w", best.Upstream, err)
	}

	return Result{
		Version: best.Transformed, UpstreamTag: best.Upstream, CommitSHA: sha,
		TagsConsidered: stats.Total, TagsSkipped: stats.Skipped,
	}, nil
}

func splitIdentifier(id string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(id, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid GitHub identifier: %s", id)
	}
	return owner, repo, nil
}
