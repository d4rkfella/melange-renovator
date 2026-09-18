package versioning

import (
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/config"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// OCITagLister lists the tags published for an OCI repository. The
// production implementation wraps go-containerregistry.
type OCITagLister interface {
	ListTags(ctx context.Context, identifier string) ([]string, error)
}

// OCIResolver resolves versions from an OCI registry's tag list, per
// config.OCIMonitor.
type OCIResolver struct {
	Lister  OCITagLister
	Monitor *config.OCIMonitor
}

func (r OCIResolver) Resolve(ctx context.Context, patterns Patterns) (Result, error) {
	tags, err := r.Lister.ListTags(ctx, r.Monitor.Identifier)
	if err != nil {
		return Result{}, fmt.Errorf("listing OCI tags for %s: %w", r.Monitor.Identifier, err)
	}
	if len(tags) == 0 {
		return Result{}, fmt.Errorf("no tags found for OCI image %s", r.Monitor.Identifier)
	}

	best, stats, err := ResolveBest(ctx, tags, r.Monitor, patterns)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Version: best.Transformed, UpstreamTag: best.Upstream,
		TagsConsidered: stats.Total, TagsSkipped: stats.Skipped,
	}, nil
}

type ociRegistry struct{}

// NewOCITagLister builds the production OCITagLister.
func NewOCITagLister() OCITagLister { return ociRegistry{} }

func (ociRegistry) ListTags(ctx context.Context, identifier string) ([]string, error) {
	repo, err := name.NewRepository(identifier)
	if err != nil {
		return nil, fmt.Errorf("parsing OCI identifier: %w", err)
	}
	tags, err := remote.List(repo, remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("listing OCI tags for %s: %w", identifier, err)
	}
	return tags, nil
}
