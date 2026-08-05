package renovator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-github/v81/github"
)

func shouldSkipVersion(ctx context.Context, tag string, versionHandler config.VersionHandler, compiledIgnore []*regexp.Regexp) bool {
	log := clog.FromContext(ctx)

	if p := versionHandler.GetFilterPrefix(); p != "" && !strings.HasPrefix(tag, p) {
		log.Debug("Version skipped: does not match tag-filter-prefix", "tag", tag, "tag-filter-prefix", p)
		return true
	}
	if c := versionHandler.GetFilterContains(); c != "" && !strings.Contains(tag, c) {
		log.Debug("Version skipped: does not match tag-filter-contains", "tag", tag, "tag-filter-contains", c)
		return true
	}

	for _, re := range compiledIgnore {
		if re.MatchString(tag) {
			log.Debug("Version skipped: matched ignore-regex-patterns entry", "tag", tag, "pattern", re.String())
			return true
		}
	}

	return false
}

func applyVersionTransforms(upstream string, versionHandler config.VersionHandler, transforms []compiledVersionTransform) string {
	transformed := strings.TrimPrefix(upstream, versionHandler.GetStripPrefix())
	transformed = strings.TrimSuffix(transformed, versionHandler.GetStripSuffix())

	for _, t := range transforms {
		transformed = t.Re.ReplaceAllString(transformed, t.Replace)
	}

	return transformed
}

func resolveLatestVersion(
	ctx context.Context,
	versions []string,
	versionHandler config.VersionHandler,
	patterns compiledPatterns,
) (*versionCandidate, resolveStats, error) {
	log := clog.FromContext(ctx)
	var best *versionCandidate
	stats := resolveStats{Total: len(versions)}

	for _, upstream := range versions {
		if shouldSkipVersion(ctx, upstream, versionHandler, patterns.IgnorePatterns) {
			stats.Skipped++
			continue
		}

		transformed := applyVersionTransforms(upstream, versionHandler, patterns.VersionTransforms)
		if transformed != upstream {
			log.Debug("Version transform applied", "upstream", upstream, "transformed", transformed)
		}

		ver, err := apk.ParseVersion(transformed)
		if err != nil {
			stats.Skipped++
			if transformed != upstream {
				log.Debug("Version skipped: APK version parsing failed after transform — check your version-transform regex",
					"upstream", upstream,
					"transformed", transformed,
					"error", err)
			} else {
				log.Debug("Version skipped: not a valid APK version", "upstream", upstream, "error", err)
			}
			continue
		}

		if best == nil || apk.CompareVersions(ver, best.ApkVer) > 0 {
			best = &versionCandidate{
				Upstream:    upstream,
				Transformed: transformed,
				ApkVer:      ver,
			}
		}
	}

	if best == nil {
		return nil, stats, fmt.Errorf("all upstream tags were filtered out or could not be parsed as valid APK versions")
	}

	if best.Upstream != best.Transformed {
		log.Debug("Resolved version string used for comparison", "tag", best.Transformed)
	} else {
		log.Debug("Resolved version string used for comparison", "tag", best.Upstream)
	}

	return best, stats, nil
}

func getLatestGitHubVersion(ctx context.Context, ghClient *github.Client, cfg *config.Configuration, patterns compiledPatterns) (versionResult, error) {
	gh := cfg.Update.GitHubMonitor
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return versionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	opts := &github.ListOptions{PerPage: 100}

	if gh.UseTags {
		type tagEntry struct {
			name string
			sha  string
		}
		var allTags []tagEntry

		for {
			tags, resp, err := ghClient.Repositories.ListTags(ctx, owner, repo, opts)
			if err != nil {
				return versionResult{}, fmt.Errorf("listing tags: %w", err)
			}
			for _, t := range tags {
				allTags = append(allTags, tagEntry{name: t.GetName(), sha: t.GetCommit().GetSHA()})
			}
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}

		if len(allTags) == 0 {
			return versionResult{}, fmt.Errorf("no tags found for GitHub repository %s/%s", owner, repo)
		}

		tagNames := make([]string, len(allTags))
		for i, t := range allTags {
			tagNames[i] = t.name
		}

		best, stats, err := resolveLatestVersion(ctx, tagNames, gh, patterns)
		if err != nil {
			return versionResult{}, fmt.Errorf("no valid tags found for %s/%s: %w", owner, repo, err)
		}

		for _, t := range allTags {
			if t.name == best.Upstream {
				return versionResult{
					Version:        best.Transformed,
					UpstreamTag:    best.Upstream,
					CommitSHA:      t.sha,
					TagsConsidered: stats.Total,
					TagsSkipped:    stats.Skipped,
				}, nil
			}
		}
		return versionResult{}, fmt.Errorf("failed to resolve SHA for tag %s", best.Upstream)
	}

	var allTagNames []string

	for {
		releases, resp, err := ghClient.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return versionResult{}, fmt.Errorf("listing releases: %w", err)
		}
		for _, r := range releases {
			if !cfg.Update.EnablePreReleaseTags && r.GetPrerelease() {
				continue
			}
			allTagNames = append(allTagNames, r.GetTagName())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	if len(allTagNames) == 0 {
		return versionResult{}, fmt.Errorf("no releases found for GitHub repository %s/%s", owner, repo)
	}

	best, stats, err := resolveLatestVersion(ctx, allTagNames, gh, patterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("no valid versions found for %s/%s: %w", owner, repo, err)
	}

	ref, _, err := ghClient.Git.GetRef(ctx, owner, repo, "refs/tags/"+best.Upstream)
	if err != nil {
		return versionResult{}, fmt.Errorf("fetching ref for tag %s: %w", best.Upstream, err)
	}
	if ref.Object == nil {
		return versionResult{}, fmt.Errorf("ref object missing for tag %s", best.Upstream)
	}

	sha := ref.Object.GetSHA()
	if ref.Object.GetType() == "tag" {
		tagObj, _, err := ghClient.Git.GetTag(ctx, owner, repo, sha)
		if err != nil {
			return versionResult{}, fmt.Errorf("resolving annotated tag %s: %w", best.Upstream, err)
		}
		if tagObj.Object != nil {
			sha = tagObj.Object.GetSHA()
		}
	}

	return versionResult{
		Version:        best.Transformed,
		UpstreamTag:    best.Upstream,
		CommitSHA:      sha,
		TagsConsidered: stats.Total,
		TagsSkipped:    stats.Skipped,
	}, nil
}

func gitCheckoutRepoURL(cfg *config.Configuration) string {
	for _, step := range cfg.Pipeline {
		if step.Uses == "git-checkout" {
			if repo := step.With["repository"]; repo != "" {
				return repo
			}
		}
	}
	return ""
}

func getLatestGitVersion(ctx context.Context, cfg *config.Configuration, patterns compiledPatterns) (versionResult, error) {
	log := clog.FromContext(ctx)
	gitMonitor := cfg.Update.GitMonitor

	repoURL := gitCheckoutRepoURL(cfg)
	if repoURL == "" {
		return versionResult{}, fmt.Errorf("no git-checkout step found in pipeline")
	}
	log.Debug("Queried git repository", "repo", repoURL)

	storage := memory.NewStorage()
	rem := git.NewRemote(storage, &gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return versionResult{}, fmt.Errorf("listing remote refs: %w", err)
	}

	var rawTags []tagRef
	for _, ref := range refs {
		if ref.Name().IsTag() {
			rawTags = append(rawTags, tagRef{
				Name: ref.Name().Short(),
				Hash: ref.Hash(),
			})
			log.Debug("Found remote tag", "tag", ref.Name().Short())
		}
	}
	if len(rawTags) == 0 {
		return versionResult{}, fmt.Errorf("no tags found in repository %s", repoURL)
	}

	tagNames := make([]string, len(rawTags))
	tagHashMap := make(map[string]plumbing.Hash, len(rawTags))
	for i, t := range rawTags {
		tagNames[i] = t.Name
		tagHashMap[t.Name] = t.Hash
	}

	best, stats, err := resolveLatestVersion(ctx, tagNames, gitMonitor, patterns)
	if err != nil {
		return versionResult{}, err
	}

	refSpec := gitconfig.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", best.Upstream, best.Upstream))
	if err := rem.FetchContext(ctx, &git.FetchOptions{
		RefSpecs: []gitconfig.RefSpec{refSpec},
		Depth:    1,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		return versionResult{}, fmt.Errorf("fetching tag %s: %w", best.Upstream, err)
	}

	upstreamHash := tagHashMap[best.Upstream]
	resolvedSHA := ""
	if tagObj, err := object.GetTag(storage, upstreamHash); err == nil {
		if commitObj, err := object.GetCommit(storage, tagObj.Target); err == nil {
			resolvedSHA = commitObj.Hash.String()
		}
	} else if commitObj, err := object.GetCommit(storage, upstreamHash); err == nil {
		resolvedSHA = commitObj.Hash.String()
	}

	if resolvedSHA == "" {
		return versionResult{}, fmt.Errorf("failed to resolve commit for tag %s", best.Upstream)
	}

	return versionResult{
		Version:        best.Transformed,
		UpstreamTag:    best.Upstream,
		CommitSHA:      resolvedSHA,
		TagsConsidered: stats.Total,
		TagsSkipped:    stats.Skipped,
	}, nil
}

func getLatestReleaseMonitorVersion(ctx context.Context, cfg *config.Configuration, patterns compiledPatterns) (versionResult, error) {
	log := clog.FromContext(ctx)
	rm := cfg.Update.ReleaseMonitor
	url := fmt.Sprintf("https://release-monitoring.org/api/v2/versions/?project_id=%d", rm.Identifier)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
		chromedp.WindowSize(1920, 1080),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	chromeCtx, cancel = context.WithTimeout(chromeCtx, 90*time.Second)
	defer cancel()

	token := os.Getenv("RELEASE_MONITOR_TOKEN")
	headers := map[string]any{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	}

	var jsonBody string
	err := chromedp.Run(chromeCtx,
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(url),
		chromedp.Sleep(15*time.Second),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerText`, &jsonBody),
	)
	if err != nil {
		return versionResult{}, fmt.Errorf("failed to fetch: %w", err)
	}

	log.Debug("previewing response", "response_preview", truncateString(jsonBody, 200))

	if strings.Contains(jsonBody, "Access Denied") || strings.Contains(jsonBody, "Making sure you're not a bot") {
		return versionResult{}, fmt.Errorf("blocked by Anubis: %s", truncateString(jsonBody, 100))
	}

	var project struct {
		LatestVersion  string   `json:"latest_version"`
		Versions       []string `json:"versions"`
		StableVersions []string `json:"stable_versions"`
	}
	if err := json.Unmarshal([]byte(jsonBody), &project); err != nil {
		return versionResult{}, fmt.Errorf("failed to decode response body: %w", err)
	}

	versions := project.StableVersions
	if cfg.Update.EnablePreReleaseTags {
		versions = project.Versions
	}

	if len(versions) == 0 {
		return versionResult{}, fmt.Errorf("no versions found in release-monitor response for project %d", rm.Identifier)
	}

	best, stats, err := resolveLatestVersion(ctx, versions, rm, patterns)
	if err != nil {
		return versionResult{}, err
	}

	return versionResult{
		Version:        best.Transformed,
		UpstreamTag:    best.Upstream,
		TagsConsidered: stats.Total,
		TagsSkipped:    stats.Skipped,
	}, nil
}

func getLatestOCIVersion(ctx context.Context, cfg *config.Configuration, patterns compiledPatterns) (versionResult, error) {
	oci := cfg.Update.OCIMonitor

	repo, err := name.NewRepository(oci.Identifier)
	if err != nil {
		return versionResult{}, fmt.Errorf("parsing OCI identifier: %w", err)
	}

	tags, err := remote.List(repo, remote.WithContext(ctx))
	if err != nil {
		return versionResult{}, fmt.Errorf("listing OCI tags for %s: %w", oci.Identifier, err)
	}

	if len(tags) == 0 {
		return versionResult{}, fmt.Errorf("no tags found for OCI image %s", oci.Identifier)
	}

	best, stats, err := resolveLatestVersion(ctx, tags, oci, patterns)
	if err != nil {
		return versionResult{}, err
	}

	return versionResult{
		Version:        best.Transformed,
		UpstreamTag:    best.Upstream,
		TagsConsidered: stats.Total,
		TagsSkipped:    stats.Skipped,
	}, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

func compilePatterns(cfg *config.Configuration) (compiledPatterns, error) {
	ignorePatterns := make([]*regexp.Regexp, 0, len(cfg.Update.IgnoreRegexPatterns))
	for _, p := range cfg.Update.IgnoreRegexPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return compiledPatterns{}, fmt.Errorf("invalid ignore pattern regex %q: %w", p, err)
		}
		ignorePatterns = append(ignorePatterns, re)
	}

	transforms := make([]compiledVersionTransform, 0, len(cfg.Update.VersionTransform))
	for _, t := range cfg.Update.VersionTransform {
		re, err := regexp.Compile(t.Match)
		if err != nil {
			return compiledPatterns{}, fmt.Errorf("invalid version transform regex %q: %w", t.Match, err)
		}
		transforms = append(transforms, compiledVersionTransform{Re: re, Replace: t.Replace})
	}

	return compiledPatterns{IgnorePatterns: ignorePatterns, VersionTransforms: transforms}, nil
}

func transformsToInfo(ts []config.VersionTransform) []vtInfo {
	out := make([]vtInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, vtInfo{Match: t.Match, Replace: t.Replace})
	}
	return out
}

func buildMonitorConfig(cfg *config.Configuration) monitorConfig {
	common := func(vh config.VersionHandler) monitorConfig {
		return monitorConfig{
			FilterPrefix:        vh.GetFilterPrefix(),
			FilterContains:      vh.GetFilterContains(),
			StripPrefix:         vh.GetStripPrefix(),
			StripSuffix:         vh.GetStripSuffix(),
			VersionTransforms:   transformsToInfo(cfg.Update.VersionTransform),
			IgnoreRegexPatterns: cfg.Update.IgnoreRegexPatterns,
		}
	}

	switch {
	case cfg.Update.GitHubMonitor != nil:
		gh := cfg.Update.GitHubMonitor
		mc := common(gh)
		mc.Type = "github-releases"
		if gh.UseTags {
			mc.Type = "github-tags"
		}
		mc.Identifier = gh.Identifier
		mc.UseTags = gh.UseTags
		mc.EnablePreReleaseTags = cfg.Update.EnablePreReleaseTags
		return mc

	case cfg.Update.GitMonitor != nil:
		mc := common(cfg.Update.GitMonitor)
		mc.Type = "git-refs"
		mc.Identifier = gitCheckoutRepoURL(cfg)
		return mc

	case cfg.Update.ReleaseMonitor != nil:
		rm := cfg.Update.ReleaseMonitor
		mc := common(rm)
		mc.Type = "release-monitor"
		mc.Identifier = fmt.Sprintf("%d", rm.Identifier)
		mc.EnablePreReleaseTags = cfg.Update.EnablePreReleaseTags
		return mc

	case cfg.Update.OCIMonitor != nil:
		oci := cfg.Update.OCIMonitor
		mc := common(oci)
		mc.Type = "oci"
		mc.Identifier = oci.Identifier
		return mc
	}

	return monitorConfig{Type: "none"}
}

func compareVersions(ctx context.Context, currentStr, latestStr string) int {
	log := clog.FromContext(ctx)

	current, err := apk.ParseVersion(currentStr)
	if err != nil {
		log.Warn("failed to parse current version", "tag", currentStr, "error", err)
		return -1
	}

	latest, err := apk.ParseVersion(latestStr)
	if err != nil {
		log.Warn("failed to parse resolved version", "tag", latestStr, "error", err)
		return 1
	}
	return apk.CompareVersions(current, latest)
}
