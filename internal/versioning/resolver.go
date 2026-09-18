package versioning

import (
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/config"
)

// Result is the outcome of resolving a package's latest eligible upstream
// version.
type Result struct {
	Version        string
	UpstreamTag    string
	CommitSHA      string
	TagsConsidered int
	TagsSkipped    int
}

// Resolver finds the best upstream version for a package, given
// pre-compiled ignore/transform patterns.
type Resolver interface {
	Resolve(ctx context.Context, patterns Patterns) (Result, error)
}

// Sources bundles the narrow, per-monitor-type dependencies needed to
// build a Resolver for any package config. Only the one matching the
// package's configured monitor type is ever used, but a nil value for the
// type actually needed surfaces as a clear error from NewResolver rather
// than a panic deep inside Resolve.
type Sources struct {
	GitHub         GitHubTagSource
	Git            GitRemote
	OCI            OCITagLister
	ReleaseMonitor ReleaseMonitorFetcher
}

// NewResolver picks the right Resolver for a package config based on which
// *Monitor field is set, mirroring melange's own "exactly one monitor
// configured" convention.
func NewResolver(cfg *config.Configuration, src Sources) (Resolver, error) {
	switch {
	case cfg.Update.GitHubMonitor != nil:
		if src.GitHub == nil {
			return nil, fmt.Errorf("github monitor configured but no GitHubTagSource provided")
		}
		return GitHubResolver{
			Source:               src.GitHub,
			Monitor:              cfg.Update.GitHubMonitor,
			EnablePreReleaseTags: cfg.Update.EnablePreReleaseTags,
		}, nil

	case cfg.Update.GitMonitor != nil:
		if src.Git == nil {
			return nil, fmt.Errorf("git monitor configured but no GitRemote provided")
		}
		return GitResolver{Remote: src.Git, RepoURL: GitCheckoutRepoURL(cfg), Monitor: cfg.Update.GitMonitor}, nil

	case cfg.Update.OCIMonitor != nil:
		if src.OCI == nil {
			return nil, fmt.Errorf("oci monitor configured but no OCITagLister provided")
		}
		return OCIResolver{Lister: src.OCI, Monitor: cfg.Update.OCIMonitor}, nil

	case cfg.Update.ReleaseMonitor != nil:
		if src.ReleaseMonitor == nil {
			return nil, fmt.Errorf("release monitor configured but no ReleaseMonitorFetcher provided")
		}
		return ReleaseMonitorResolver{
			Fetcher:              src.ReleaseMonitor,
			Monitor:              cfg.Update.ReleaseMonitor,
			EnablePreReleaseTags: cfg.Update.EnablePreReleaseTags,
		}, nil

	case cfg.Update.VersionDataMonitor != nil:
		return nil, fmt.Errorf("version-data monitor is not yet implemented")

	default:
		return nil, fmt.Errorf("no update monitor configured for package")
	}
}
