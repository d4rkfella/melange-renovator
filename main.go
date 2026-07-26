package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/bump"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
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
	"golang.org/x/sync/errgroup"
)

type packageState struct {
	LastVersion string    `json:"last_version"`
	LastChecked time.Time `json:"last_checked"`
}

type discoveredConfig struct {
	Path   string
	Config *config.Configuration
}

type awsOptions struct {
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Endpoint  string
}

type versionResult struct {
	Version        string
	UpstreamTag    string
	CommitSHA      string
	TagsConsidered int
	TagsSkipped    int
}

type tagRef struct {
	Name string
	Hash plumbing.Hash
}

type compiledVersionTransform struct {
	Re      *regexp.Regexp
	Replace string
}

type versionCandidate struct {
	Upstream    string
	Transformed string
	ApkVer      apk.Version
}

type resolveStats struct {
	Total   int
	Skipped int
}

type compiledPatterns struct {
	IgnorePatterns    []*regexp.Regexp
	VersionTransforms []compiledVersionTransform
}

type vtInfo struct {
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

type monitorConfig struct {
	Type                 string   `json:"type"`
	Identifier           string   `json:"identifier,omitempty"`
	UseTags              bool     `json:"useTags,omitempty"`
	EnablePreReleaseTags bool     `json:"enablePreReleaseTags,omitempty"`
	FilterPrefix         string   `json:"filterPrefix,omitempty"`
	FilterContains       string   `json:"filterContains,omitempty"`
	StripPrefix          string   `json:"stripPrefix,omitempty"`
	StripSuffix          string   `json:"stripSuffix,omitempty"`
	VersionTransforms    []vtInfo `json:"versionTransforms,omitempty"`
	IgnoreRegexPatterns  []string `json:"ignoreRegexPatterns,omitempty"`
}

type scheduleInfo struct {
	Period string `json:"period,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type renovateDep struct {
	DepName         string        `json:"depName"`
	PackageName     string        `json:"packageName"`
	ConfigPath      string        `json:"packageFile"`
	Monitor         monitorConfig `json:"monitor"`
	Schedule        *scheduleInfo `json:"schedule,omitempty"`
	CurrentVersion  string        `json:"currentVersion"`
	ResolvedTag     string        `json:"resolvedUpstreamTag,omitempty"`
	ResolvedVersion string        `json:"resolvedTransformedVersion,omitempty"`
	ResolvedCommit  string        `json:"resolvedCommitSha,omitempty"`
	FixedVersion    string        `json:"fixedVersion,omitempty"`
	UpdateAvailable bool          `json:"updateAvailable"`
	Skipped         bool          `json:"skipped"`
	SkipReason      string        `json:"skipReason,omitempty"`
	PRUrl           string        `json:"prUrl,omitempty"`
	DryRun          bool          `json:"dryRun,omitempty"`
	Warnings        []string      `json:"warnings"`
}

type renovatePackageFile struct {
	PackageFile string        `json:"packageFile"`
	Deps        []renovateDep `json:"deps"`
}

var (
	version   = "dev"
	commitSHA = "unknown"
	buildDate = "unknown"
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

func getLatestGitHubVersion(ctx context.Context, cfg *config.Configuration, patterns compiledPatterns) (versionResult, error) {
	gh := cfg.Update.GitHubMonitor
	parts := strings.Split(gh.Identifier, "/")
	if len(parts) != 2 {
		return versionResult{}, fmt.Errorf("invalid GitHub identifier: %s", gh.Identifier)
	}
	owner, repo := parts[0], parts[1]

	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		client = client.WithAuthToken(token)
	}

	opts := &github.ListOptions{PerPage: 100}

	if gh.UseTags {
		type tagEntry struct {
			name string
			sha  string
		}
		var allTags []tagEntry

		for {
			tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
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
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, opts)
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

	ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+best.Upstream)
	if err != nil {
		return versionResult{}, fmt.Errorf("fetching ref for tag %s: %w", best.Upstream, err)
	}
	if ref.Object == nil {
		return versionResult{}, fmt.Errorf("ref object missing for tag %s", best.Upstream)
	}

	sha := ref.Object.GetSHA()
	if ref.Object.GetType() == "tag" {
		tagObj, _, err := client.Git.GetTag(ctx, owner, repo, sha)
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

func persistState(ctx context.Context, s3Client *s3.Client, bucket, stateKey string, pkgState packageState, result versionResult, updated bool) {
	log := clog.FromContext(ctx)
	pkgState.LastChecked = time.Now()
	if updated {
		pkgState.LastVersion = result.Version
	}

	if err := savePackageState(ctx, s3Client, bucket, stateKey, pkgState); err != nil {
		log.Warn("failed to persist package state to S3",
			"bucket", bucket,
			"key", stateKey,
			"error", err,
		)
	}
}

func loadPackageState(ctx context.Context, client *s3.Client, bucket, key string) (packageState, error) {
	log := clog.FromContext(ctx)

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
			if apiErr.ErrorCode() == "NoSuchKey" {
				log.Debug("no existing state found in S3, initializing new state", "key", key)
				return packageState{}, nil
			}
		}
		return packageState{}, fmt.Errorf("fetching state from S3: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var ps packageState
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return packageState{}, fmt.Errorf("decoding package state: %w", err)
	}

	return ps, nil
}

func savePackageState(ctx context.Context, client *s3.Client, bucket, key string, ps packageState) error {
	data, _ := json.Marshal(ps)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}

func shouldRunSchedule(s *config.Schedule, lastChecked time.Time) bool {
	if s == nil {
		return true
	}

	period := strings.ToLower(string(s.Period))
	if period == "" || period == "none" {
		return true
	}

	now := time.Now()
	switch period {
	case "daily":
		return now.Sub(lastChecked) >= 24*time.Hour
	case "weekly":
		return now.Sub(lastChecked) >= 7*24*time.Hour
	case "monthly":
		return now.Sub(lastChecked) >= 30*24*time.Hour
	default:
		return true
	}
}

func ensurePR(
	ctx context.Context,
	gh *github.Client,
	owner, repo string,
	filePath string,
	pkgName string,
	result versionResult,
	prBranch, prTitle, prBody string,
	sequential bool,
	dryRun bool,
) (string, []int, error) {
	log := clog.FromContext(ctx)
	var closedSuperseded []int

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("reading file: %w", err)
	}

	fileAPIPath := strings.TrimPrefix(filePath, "/github/workspace/")
	var existingFile *github.RepositoryContent

	_, resp, err := gh.Repositories.GetBranch(ctx, owner, repo, prBranch, 0)
	branchExists := err == nil
	if !branchExists && resp != nil && resp.StatusCode != 404 {
		return "", nil, fmt.Errorf("fetching branch info (status %d): %w", resp.StatusCode, err)
	}

	branchPRs, _, err := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  fmt.Sprintf("%s:%s", owner, prBranch),
	})
	if err != nil {
		return "", nil, fmt.Errorf("checking for existing branch PRs: %w", err)
	}
	prExists := len(branchPRs) > 0
	var prURL string
	if prExists {
		prURL = branchPRs[0].GetHTMLURL()
	}

	if prExists {
		if sequential {
			log.Debug("Sequential mode: open PR already exists, skipping")
			return prURL, nil, nil
		}

		remoteFile, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if err != nil {
			return "", nil, fmt.Errorf("fetching file from PR branch: %w", err)
		}
		existingFile = remoteFile
		remoteContent, _ := remoteFile.GetContent()
		if remoteContent == string(content) {
			log.Debug("content already matches branch and PR is open, nothing to do")
			return prURL, nil, nil
		}
	}

	prs, _, err := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{State: "open"})
	if err != nil {
		return "", nil, fmt.Errorf("listing all open PRs: %w", err)
	}

	for _, pr := range prs {
		if !strings.HasPrefix(pr.GetTitle(), pkgName+"/") {
			continue
		}

		if sequential {
			log.Debug("open PR exists for package, skipping (sequential)")
			return pr.GetHTMLURL(), nil, nil
		}

		hasAutomationLabel := false
		for _, label := range pr.Labels {
			if label.GetName() == "automated pr" {
				hasAutomationLabel = true
				break
			}
		}
		if !hasAutomationLabel {
			log.Debug("open PR missing automation label, skipping",
				"number", pr.GetNumber(),
				"title", pr.GetTitle(),
			)
			continue
		}

		remoteFile, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if err != nil {
			log.Warn("could not fetch config from PR branch, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}

		remoteContent, err := remoteFile.GetContent()
		if err != nil {
			log.Warn("could not decode config from PR branch, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}

		tmp, err := os.CreateTemp("", "melange-*.yaml")
		if err != nil {
			log.Warn("could not create temp file for config parsing, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}
		defer func() {
			if err := os.Remove(tmp.Name()); err != nil {
				log.Warn("could not remove temp file", "path", tmp.Name(), "error", err)
			}
		}()

		if _, err := tmp.WriteString(remoteContent); err != nil {
			if err := tmp.Close(); err != nil {
				log.Warn("could not close temp file", "path", tmp.Name(), "error", err)
			}
			log.Warn("could not write temp file for config parsing, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}
		if err := tmp.Close(); err != nil {
			log.Warn("could not close temp file for config parsing, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}

		remoteCfg, err := config.ParseConfiguration(ctx, tmp.Name())
		if err != nil {
			log.Warn("could not parse config from PR branch, skipping supersede check",
				"number", pr.GetNumber(),
				"error", err,
			)
			continue
		}

		if compareVersions(ctx, remoteCfg.Package.Version, result.Version) >= 0 {
			log.Debug("open PR version is same or newer, skipping",
				"number", pr.GetNumber(),
				"pr_version", remoteCfg.Package.Version,
				"new_version", result.Version,
			)
			continue
		}

		if dryRun {
			log.Info("DRY RUN: would close superseded PR and open new one",
				"closing_number", pr.GetNumber(),
				"closing_version", remoteCfg.Package.Version,
				"new_version", result.Version,
			)
			prExists = false
			continue
		}

		if _, _, err := gh.Issues.CreateComment(ctx, owner, repo, pr.GetNumber(), &github.IssueComment{
			Body: github.Ptr(fmt.Sprintf(
				"This PR has been superseded by a newer version update: **%s**. Closing automatically.",
				prTitle,
			)),
		}); err != nil {
			log.Warn("failed to post superseded comment", "number", pr.GetNumber(), "error", err)
		}

		log.Info("closing superseded PR",
			"number", pr.GetNumber(),
			"pr_version", remoteCfg.Package.Version,
			"new_version", result.Version,
		)
		if _, _, err := gh.PullRequests.Edit(ctx, owner, repo, pr.GetNumber(), &github.PullRequest{
			State: github.Ptr("closed"),
		}); err != nil {
			log.Warn("failed to close outdated PR", "number", pr.GetNumber(), "error", err)
		} else {
			closedSuperseded = append(closedSuperseded, pr.GetNumber())
		}

		prExists = false
	}

	if dryRun {
		return "", closedSuperseded, nil
	}

	repoInfo, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", nil, fmt.Errorf("getting repo info: %w", err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()

	ref, _, err := gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
	if err != nil {
		return "", nil, fmt.Errorf("getting default branch ref: %w", err)
	}
	headSHA := ref.Object.GetSHA()

	if !branchExists {
		_, _, err = gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
			Ref: "refs/heads/" + prBranch,
			SHA: headSHA,
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return "", nil, fmt.Errorf("creating branch: %w", err)
		}

		remoteFile, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if err != nil {
			return "", nil, fmt.Errorf("fetching file info from new branch: %w", err)
		}
		existingFile = remoteFile
	}

	if _, _, err = gh.Repositories.UpdateFile(ctx, owner, repo, fileAPIPath,
		&github.RepositoryContentFileOptions{
			Message: github.Ptr(prTitle),
			Content: content,
			SHA:     existingFile.SHA,
			Branch:  github.Ptr(prBranch),
		}); err != nil {
		return "", nil, fmt.Errorf("updating file: %w", err)
	}

	if !prExists {
		newPR, _, err := gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
			Title: github.Ptr(prTitle),
			Body:  github.Ptr(prBody),
			Head:  github.Ptr(prBranch),
			Base:  github.Ptr(defaultBranch),
		})
		if err != nil {
			return "", nil, fmt.Errorf("creating PR: %w", err)
		}

		if _, _, err = gh.Issues.AddLabelsToIssue(ctx, owner, repo, newPR.GetNumber(),
			[]string{"automated pr", "request-version-update"}); err != nil {
			log.Warn("failed to add labels", "error", err)
		}

		log.Info("PR is ready!", "url", newPR.GetHTMLURL())
		prURL = newPR.GetHTMLURL()
	}

	return prURL, closedSuperseded, nil
}

func bumpConfig(ctx context.Context, configPath, newVersion, expectedCommit string) error {
	rc, err := renovate.New(renovate.WithConfig(configPath))
	if err != nil {
		return fmt.Errorf("creating renovate client: %w", err)
	}

	ren := bump.New(ctx,
		bump.WithTargetVersion(newVersion),
		bump.WithExpectedCommit(expectedCommit),
	)

	if err := rc.Renovate(ctx, ren); err != nil {
		return fmt.Errorf("renovating config: %w", err)
	}

	return nil
}

func discoverConfigs(ctx context.Context) ([]discoveredConfig, error) {
	log := clog.FromContext(ctx)
	var found []discoveredConfig

	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	err = filepath.WalkDir(cwd, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Warn("Directory walk error", "path", path, "error", err)
			return nil
		}

		name := d.Name()

		if d.IsDir() {
			if strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasPrefix(name, ".") {
			return nil
		}

		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		cfg, err := config.ParseConfiguration(ctx, path)
		if err != nil {
			log.Debug("Failed to parse as valid melange configuration", "path", path, "error", err)
			return nil
		}

		if !cfg.Update.Enabled {
			log.Debug("Skipping config: updates are disabled/not configured",
				"path", path,
			)
			return nil
		}

		found = append(found, discoveredConfig{
			Path:   path,
			Config: cfg,
		})

		return nil
	})

	return found, err
}

func main() {
	logLevelFlag := flag.String("log-level", "info", "Log level")
	dryRunFlag := flag.Bool("dry-run", false, "Saves PR metadata to a local file if a new PR is to be opened and skips the schedule logic dependant on the S3 backend.")
	concurrencyFlag := flag.Int("concurrency", 5, "Number of parallel workers")

	s3BucketFlag := flag.String("s3-bucket", "", "AWS S3 bucket for state")
	awsRegionFlag := flag.String("aws-region", "us-east-1", "AWS region")
	awsAccessKeyFlag := flag.String("aws-access-key", "", "AWS access key ID")
	awsSecretKeyFlag := flag.String("aws-secret-key", "", "AWS secret access key")
	awsEndpointFlag := flag.String("aws-endpoint", "", "Custom S3 endpoint URL")

	flag.Parse()

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(*logLevelFlag)); err != nil {
		logLevel = slog.LevelInfo
	}

	logger := clog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	ctx := clog.WithLogger(context.Background(), logger)
	log := clog.FromContext(ctx)

	log.Info("Starting melange-renovator", "version", version, "commit", commitSHA, "build_date", buildDate)
	log.Info("Runtime Environment", "GOOS", runtime.GOOS, "GOARCH", runtime.GOARCH, "GoVersion", runtime.Version())

	if !*dryRunFlag {
		if *s3BucketFlag == "" {
			log.Error("S3 bucket is required in non-dry-run mode", "hint", "set -s3-bucket or use -dry-run")
			os.Exit(1)
		}
		if os.Getenv("GITHUB_TOKEN") == "" {
			log.Error("GITHUB_TOKEN is required in non-dry-run mode", "hint", "set GITHUB_TOKEN or use -dry-run")
			os.Exit(1)
		}
		if os.Getenv("GITHUB_REPOSITORY") == "" {
			log.Error("GITHUB_REPOSITORY is required in non-dry-run mode", "hint", "set GITHUB_REPOSITORY or use -dry-run")
			os.Exit(1)
		}
	}

	discoveredConfigs, err := discoverConfigs(ctx)
	if err != nil {
		log.Error("Melange-renovator failed during auto-discovery", "error", err)
		os.Exit(1)
	}

	if len(discoveredConfigs) == 0 {
		log.Warn("No valid melange configs were discovered in the current working directory")
		os.Exit(0)
	}

	configPaths := make([]string, len(discoveredConfigs))
	for i, c := range discoveredConfigs {
		configPaths[i] = c.Path
	}
	log.Info("Discovered melange configs with updates enabled",
		"count", len(discoveredConfigs),
		"paths", configPaths,
	)

	awsOpts := awsOptions{
		Bucket:    *s3BucketFlag,
		Region:    *awsRegionFlag,
		AccessKey: *awsAccessKeyFlag,
		SecretKey: *awsSecretKeyFlag,
		Endpoint:  *awsEndpointFlag,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(*concurrencyFlag)

	var successCount atomic.Int64
	var failureCount atomic.Int64

	var reportMu sync.Mutex
	var report []renovatePackageFile

	for _, item := range discoveredConfigs {
		g.Go(func() error {
			dep, err := run(ctx, item.Path, item.Config, *dryRunFlag, awsOpts)
			if err != nil {
				clog.FromContext(ctx).Error("error processing melange config", "error", err, "config_path", item.Path)
				failureCount.Add(1)
				if dep == nil {
					dep = &renovateDep{
						DepName:     item.Config.Package.Name,
						PackageName: item.Config.Package.Name,
						ConfigPath:  item.Path,
						Monitor:     buildMonitorConfig(item.Config),
						Warnings:    []string{err.Error()},
					}
				} else {
					dep.Warnings = append(dep.Warnings, err.Error())
				}
			} else {
				successCount.Add(1)
			}

			reportMu.Lock()
			report = append(report, renovatePackageFile{
				PackageFile: item.Path,
				Deps:        []renovateDep{*dep},
			})
			reportMu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		log.Error("Melange-renovator execution halted due to a fatal error", "error", err)
		os.Exit(1)
	}

	log.Info("Melange-renovator finished processing all discovered config files",
		"total", len(discoveredConfigs),
		"succeeded", successCount.Load(),
		"failed", failureCount.Load(),
	)

	sort.Slice(report, func(i, j int) bool {
		return report[i].PackageFile < report[j].PackageFile
	})

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error("failed to marshal JSON report", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(data))

}

func run(ctx context.Context, filePath string, cfg *config.Configuration, dryRun bool, awsOpts awsOptions) (*renovateDep, error) {
	ctx = clog.WithLogger(ctx, clog.FromContext(ctx).With(
		"package_name", cfg.Package.Name,
		"current_version", cfg.Package.Version,
		"config_path", filePath,
	))
	log := clog.FromContext(ctx)

	dep := &renovateDep{
		DepName:        cfg.Package.Name,
		PackageName:    cfg.Package.Name,
		ConfigPath:     filePath,
		Monitor:        buildMonitorConfig(cfg),
		CurrentVersion: cfg.Package.Version,
		Warnings:       []string{},
		DryRun:         dryRun,
	}
	if cfg.Update.Schedule != nil {
		dep.Schedule = &scheduleInfo{
			Period: string(cfg.Update.Schedule.Period),
			Reason: cfg.Update.Schedule.Reason,
		}
	}

	patterns, err := compilePatterns(cfg)
	if err != nil {
		dep.Skipped = true
		dep.SkipReason = err.Error()
		return dep, fmt.Errorf("compiling patterns: %w", err)
	}

	var s3Client *s3.Client
	var pkgState packageState
	stateKey := fmt.Sprintf("state/%s.json", cfg.Package.Name)

	if !dryRun {
		var optFns []func(*awscfg.LoadOptions) error
		if awsOpts.Region != "" {
			optFns = append(optFns, awscfg.WithRegion(awsOpts.Region))
		}
		if awsOpts.AccessKey != "" && awsOpts.SecretKey != "" {
			creds := credentials.NewStaticCredentialsProvider(awsOpts.AccessKey, awsOpts.SecretKey, "")
			optFns = append(optFns, awscfg.WithCredentialsProvider(creds))
		}

		awsConfig, err := awscfg.LoadDefaultConfig(ctx, optFns...)
		if err != nil {
			dep.Skipped = true
			dep.SkipReason = err.Error()
			return dep, fmt.Errorf("loading AWS config: %w", err)
		}

		s3Client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
			if awsOpts.Endpoint != "" {
				o.BaseEndpoint = aws.String(awsOpts.Endpoint)
			}
		})

		pkgState, err = loadPackageState(ctx, s3Client, awsOpts.Bucket, stateKey)
		if err != nil {
			dep.Skipped = true
			dep.SkipReason = err.Error()
			return dep, fmt.Errorf("loading package state from S3: %w", err)
		}

		if !shouldRunSchedule(cfg.Update.Schedule, pkgState.LastChecked) {
			log.Debug("Skipping config: not due per schedule",
				"schedule", cfg.Update.Schedule,
				"schedule_reason", cfg.Update.Schedule.Reason,
				"last_checked", pkgState.LastChecked,
			)
			dep.Skipped = true
			dep.SkipReason = "not due per schedule"
			dep.FixedVersion = cfg.Package.Version
			return dep, nil
		}
	}

	if cfg.Update.GitHubMonitor != nil && os.Getenv("GITHUB_TOKEN") == "" {
		dep.Warnings = append(dep.Warnings,
			"GITHUB_TOKEN is not set; GitHub API calls for this package will use the unauthenticated rate limit (60 req/hr)")
	}

	var result versionResult
	switch {
	case cfg.Update.GitHubMonitor != nil:
		result, err = getLatestGitHubVersion(ctx, cfg, patterns)
	case cfg.Update.ReleaseMonitor != nil:
		result, err = getLatestReleaseMonitorVersion(ctx, cfg, patterns)
	case cfg.Update.GitMonitor != nil:
		result, err = getLatestGitVersion(ctx, cfg, patterns)
	case cfg.Update.OCIMonitor != nil:
		result, err = getLatestOCIVersion(ctx, cfg, patterns)
	default:
		dep.Skipped = true
		dep.SkipReason = "no update monitor configured for package"
		return dep, fmt.Errorf("no update monitor configured for package")
	}
	if err != nil {
		dep.Skipped = true
		dep.SkipReason = err.Error()
		return dep, fmt.Errorf("fetching upstream version: %w", err)
	}

	dep.ResolvedTag = result.UpstreamTag
	dep.ResolvedVersion = result.Version
	dep.ResolvedCommit = result.CommitSHA

	if result.TagsSkipped > 0 {
		dep.Warnings = append(dep.Warnings, fmt.Sprintf(
			"%d of %d upstream versions were filtered out by prefix/contains/ignore-regex rules or failed APK version parsing (run with -log-level=debug for details)",
			result.TagsSkipped, result.TagsConsidered))
	}

	if compareVersions(ctx, cfg.Package.Version, result.Version) >= 0 {
		dep.FixedVersion = cfg.Package.Version
		dep.UpdateAvailable = false
		if s3Client != nil {
			persistState(ctx, s3Client, awsOpts.Bucket, stateKey, pkgState, result, false)
		}
		return dep, nil
	}

	dep.UpdateAvailable = true

	prBranch := fmt.Sprintf("update-%s", cfg.Package.Name)
	prTitle := fmt.Sprintf("%s/%s package update", cfg.Package.Name, result.Version)
	prBody := "<p align=\"center\">\n" +
		"  <img src=\"https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg\" />\n" +
		"</p>"

	if err := bumpConfig(ctx, filePath, result.Version, result.CommitSHA); err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return dep, fmt.Errorf("bumping config: %w", err)
	}

	if dryRun {
		dryRunPath := filePath + ".dry-run"
		content := fmt.Sprintf("BRANCH: %s\nTITLE: %s\nBODY: %s\n", prBranch, prTitle, prBody)
		if err := os.WriteFile(dryRunPath, []byte(content), 0644); err != nil {
			log.Warn("Failed to write dry-run artifact", "path", dryRunPath, "error", err)
			dep.Warnings = append(dep.Warnings, fmt.Sprintf("failed to write dry-run artifact: %v", err))
		} else {
			log.Info("DRY RUN: wrote PR metadata to disk", "path", dryRunPath)
		}
		return dep, nil
	}

	repoEnv := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(repoEnv, "/")
	if len(parts) != 2 {
		dep.Warnings = append(dep.Warnings, fmt.Sprintf("invalid GITHUB_REPOSITORY format %q", repoEnv))
		return dep, fmt.Errorf("invalid GITHUB_REPOSITORY format %q: expected owner/repo", repoEnv)
	}

	ghClient := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	prURL, closedSuperseded, err := ensurePR(ctx, ghClient, parts[0], parts[1],
		filePath, cfg.Package.Name,
		result,
		prBranch, prTitle, prBody,
		cfg.Update.RequireSequential, dryRun,
	)
	if err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return dep, err
	}
	dep.PRUrl = prURL
	if len(closedSuperseded) > 0 {
		numbers := make([]string, len(closedSuperseded))
		for i, n := range closedSuperseded {
			numbers[i] = fmt.Sprintf("#%d", n)
		}
		dep.Warnings = append(dep.Warnings, fmt.Sprintf(
			"closed superseded PR(s) %s in favor of this update", strings.Join(numbers, ", ")))
	}

	persistState(ctx, s3Client, awsOpts.Bucket, stateKey, pkgState, result, true)
	return dep, nil
}
