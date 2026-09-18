// internal/versioning/git_remote.go
package versioning

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

// gitRemote is the production GitRemote, backed by go-git against an
// in-memory remote — no local clone needed just to list or resolve tags.
// ListTags and ResolveTagCommit are independent, idempotent remote
// round-trips rather than sharing one in-memory session the way the
// original combined list+fetch in a single function scope; that costs one
// extra round trip on an update but keeps each method testable and
// correct on its own.
type gitRemote struct{}

// NewGitRemote builds the production GitRemote implementation.
func NewGitRemote() GitRemote { return gitRemote{} }

func (gitRemote) ListTags(ctx context.Context, url string) ([]GitTag, error) {
	storage := memory.NewStorage()
	rem := git.NewRemote(storage, &gitconfig.RemoteConfig{Name: "origin", URLs: []string{url}})

	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing remote refs: %w", err)
	}

	var tags []GitTag
	for _, ref := range refs {
		if ref.Name().IsTag() {
			tags = append(tags, GitTag{Name: ref.Name().Short(), SHA: ref.Hash().String()})
		}
	}
	return tags, nil
}

func (gitRemote) ResolveTagCommit(ctx context.Context, url, tag string) (string, error) {
	storage := memory.NewStorage()
	rem := git.NewRemote(storage, &gitconfig.RemoteConfig{Name: "origin", URLs: []string{url}})

	refSpec := gitconfig.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", tag, tag))
	if err := rem.FetchContext(ctx, &git.FetchOptions{RefSpecs: []gitconfig.RefSpec{refSpec}, Depth: 1}); err != nil && err != git.NoErrAlreadyUpToDate {
		return "", fmt.Errorf("fetching tag %s: %w", tag, err)
	}

	ref, err := storage.Reference(plumbing.NewTagReferenceName(tag))
	if err != nil {
		return "", fmt.Errorf("resolving fetched tag ref: %w", err)
	}
	if tagObj, err := object.GetTag(storage, ref.Hash()); err == nil {
		if commit, err := object.GetCommit(storage, tagObj.Target); err == nil {
			return commit.Hash.String(), nil
		}
	}
	if commit, err := object.GetCommit(storage, ref.Hash()); err == nil {
		return commit.Hash.String(), nil
	}
	return "", fmt.Errorf("failed to resolve commit for tag %s", tag)
}
