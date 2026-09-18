package ghrepo

import (
	"context"
	"fmt"

	"github.com/d4rkfella/melange-renovator/internal/versioning"
	"github.com/google/go-github/v81/github"
)

func NewTagSource(gh GitHubAPI) versioning.GitHubTagSource {
	return &liveClient{gh: gh}
}

func (c *liveClient) ListTags(ctx context.Context, owner, repo string) ([]versioning.TagCommit, error) {
	opts := &github.ListOptions{PerPage: 100}
	var all []versioning.TagCommit
	for {
		tags, resp, err := c.gh.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing tags: %w", err)
		}
		for _, t := range tags {
			all = append(all, versioning.TagCommit{Name: t.GetName(), SHA: t.GetCommit().GetSHA()})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

func (c *liveClient) ListReleaseTags(ctx context.Context, owner, repo string, includePrerelease bool) ([]string, error) {
	opts := &github.ListOptions{PerPage: 100}
	var all []string
	for {
		releases, resp, err := c.gh.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing releases: %w", err)
		}
		for _, r := range releases {
			if !includePrerelease && r.GetPrerelease() {
				continue
			}
			all = append(all, r.GetTagName())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// ResolveTagCommit dereferences a tag down to the commit it ultimately
// points at — annotated tags reference a tag object, not a commit
// directly, so that case needs one extra lookup.
func (c *liveClient) ResolveTagCommit(ctx context.Context, owner, repo, tag string) (string, error) {
	ref, _, err := c.gh.Git.GetRef(ctx, owner, repo, "refs/tags/"+tag)
	if err != nil {
		return "", fmt.Errorf("fetching ref for tag %s: %w", tag, err)
	}
	if ref.Object == nil {
		return "", fmt.Errorf("ref object missing for tag %s", tag)
	}

	sha := ref.Object.GetSHA()
	if ref.Object.GetType() == "tag" {
		tagObj, _, err := c.gh.Git.GetTag(ctx, owner, repo, sha)
		if err != nil {
			return "", fmt.Errorf("resolving annotated tag %s: %w", tag, err)
		}
		if tagObj.Object != nil {
			sha = tagObj.Object.GetSHA()
		}
	}
	return sha, nil
}
