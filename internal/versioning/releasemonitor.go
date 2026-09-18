package versioning

import (
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/config"
)

// ReleaseProject is the subset of release-monitoring.org's project
// response this tool consumes.
type ReleaseProject struct {
	LatestVersion  string   `json:"latest_version"`
	Versions       []string `json:"versions"`
	StableVersions []string `json:"stable_versions"`
}

// ReleaseMonitorFetcher fetches a project's version list from
// release-monitoring.org. The production implementation drives headless
// Chrome — the API sits behind Anubis bot-detection, so a plain HTTP GET
// doesn't work — but that's entirely hidden behind this interface. Tests
// can substitute a fake that returns a canned ReleaseProject with no
// browser involved at all, which was impossible in the original code.
type ReleaseMonitorFetcher interface {
	FetchProject(ctx context.Context, projectID int) (ReleaseProject, error)
}

// ReleaseMonitorResolver resolves versions from release-monitoring.org,
// per config.ReleaseMonitor.
type ReleaseMonitorResolver struct {
	Fetcher              ReleaseMonitorFetcher
	Monitor              *config.ReleaseMonitor
	EnablePreReleaseTags bool
}

func (r ReleaseMonitorResolver) Resolve(ctx context.Context, patterns Patterns) (Result, error) {
	project, err := r.Fetcher.FetchProject(ctx, r.Monitor.Identifier)
	if err != nil {
		return Result{}, err
	}

	versions := project.StableVersions
	if r.EnablePreReleaseTags {
		versions = project.Versions
	}
	if len(versions) == 0 {
		return Result{}, fmt.Errorf("no versions found in release-monitor response for project %d", r.Monitor.Identifier)
	}

	best, stats, err := ResolveBest(ctx, versions, r.Monitor, patterns)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Version: best.Transformed, UpstreamTag: best.Upstream,
		TagsConsidered: stats.Total, TagsSkipped: stats.Skipped,
	}, nil
}
