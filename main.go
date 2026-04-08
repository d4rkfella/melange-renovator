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
	"strings"
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
	Version   string
	CommitSHA string
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

var (
	version   = "dev"
	commitSHA = "unknown"
	buildDate = "unknown"
)

func shouldSkipVersion(tag string, versionHandler config.VersionHandler, compiledIgnore []*regexp.Regexp, logger *slog.Logger) bool {
	if p := versionHandler.GetFilterPrefix(); p != "" && !strings.HasPrefix(tag, p) {
		logger.Debug("Version skipped: does not match tag-filter-prefix", "tag", tag, "tag-filter-prefix", p)
		return true
	}
	if c := versionHandler.GetFilterContains(); c != "" && !strings.Contains(tag, c) {
		logger.Debug("Version skipped: does not match tag-filter-contains", "tag", tag, "tag-filter-contains", c)
		return true
	}

	for _, re := range compiledIgnore {
		if re.MatchString(tag) {
			logger.Debug("Version skipped: matched ignore-regex-patterns entry", "tag", tag, "pattern", re.String())
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
	versions []string,
	versionHandler config.VersionHandler,
	compiledIgnore []*regexp.Regexp,
	transforms []compiledVersionTransform,
	logger *slog.Logger,
) (*versionCandidate, error) {
	var best *versionCandidate

	for _, upstream := range versions {
		if shouldSkipVersion(upstream, versionHandler, compiledIgnore, logger) {
			continue
		}

		transformed := applyVersionTransforms(upstream, versionHandler, transforms)
		if transformed != upstream {
			logger.Debug("Version transform applied", "upstream", upstream, "transformed", transformed)
		}

		ver, err := apk.ParseVersion(transformed)
		if err != nil {
			if transformed != upstream {
				logger.Warn("Version skipped: APK version parsing failed after transform — check your version-transform regex",
					"upstream", upstream,
					"transformed", transformed,
					"error", err)
			} else {
				logger.Debug("Version skipped: not a valid APK version", "upstream", upstream, "error", err)
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
		return nil, fmt.Errorf("all upstream tags were filtered out or could not be parsed as valid APK versions")
	}

	if best.Upstream != best.Transformed {
		logger.Debug("Resolved version string used for comparison", "tag", best.Transformed)
	} else {
		logger.Debug("Resolved version string used for comparison", "tag", best.Upstream)
	}

	return best, nil
}

func getLatestGitHubVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, melangeTransforms []compiledVersionTransform) (versionResult, error) {
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

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	resolveCommitSHA := func(tagName string) (string, error) {
		ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/tags/"+tagName)
		if err != nil {
			return "", fmt.Errorf("fetching ref for tag %s: %w", tagName, err)
		}
		if ref.Object == nil {
			return "", fmt.Errorf("ref object missing for tag %s", tagName)
		}

		switch ref.Object.GetType() {
		case "commit":
			return ref.Object.GetSHA(), nil
		case "tag":
			tagObj, _, err := client.Git.GetTag(ctx, owner, repo, ref.Object.GetSHA())
			if err != nil {
				return "", fmt.Errorf("resolving annotated tag %s: %w", tagName, err)
			}
			if tagObj.Object != nil {
				return tagObj.Object.GetSHA(), nil
			}
		}

		return "", fmt.Errorf("unable to resolve SHA for tag %s", tagName)
	}

	fetchAndReturn := func(best *versionCandidate) (versionResult, error) {
		sha, err := resolveCommitSHA(best.Upstream)
		if err != nil {
			return versionResult{}, err
		}
		return versionResult{
			Version:   best.Transformed,
			CommitSHA: sha,
		}, nil
	}

	if gh.UseTags {
		for {
			tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
			if err != nil {
				return versionResult{}, fmt.Errorf("listing tags: %w", err)
			}

			if len(tags) == 0 {
				return versionResult{}, fmt.Errorf("no tags found for GitHub repository %s/%s", owner, repo)
			}

			tagNames := make([]string, len(tags))
			for i := range tags {
				tagNames[i] = tags[i].GetName()
			}

			best, err := resolveLatestVersion(tagNames, gh, compiledIgnore, melangeTransforms, logger)
			if err == nil && best != nil {
				return fetchAndReturn(best)
			}

			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}

		return versionResult{}, fmt.Errorf("no valid tags found for %s/%s", owner, repo)
	}

	for {
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return versionResult{}, fmt.Errorf("listing releases: %w", err)
		}

		if len(releases) == 0 {
			return versionResult{}, fmt.Errorf("no releases found for GitHub repository %s/%s", owner, repo)
		}

		tagNames := make([]string, 0, len(releases))
		for _, r := range releases {
			if !cfg.Update.EnablePreReleaseTags && r.GetPrerelease() {
				continue
			}
			tagNames = append(tagNames, r.GetTagName())
		}

		best, err := resolveLatestVersion(tagNames, gh, compiledIgnore, melangeTransforms, logger)
		if err == nil && best != nil {
			return fetchAndReturn(best)
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return versionResult{}, fmt.Errorf("no valid versions found for %s/%s", owner, repo)
}

func getLatestGitVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, transforms []compiledVersionTransform) (versionResult, error) {
	gitMonitor := cfg.Update.GitMonitor

	repoURL := ""
	for _, step := range cfg.Pipeline {
		if step.Uses == "git-checkout" {
			if repo := step.With["repository"]; repo != "" {
				repoURL = repo
				break
			}
		}
	}
	if repoURL == "" {
		return versionResult{}, fmt.Errorf("no git-checkout step found in pipeline")
	}
	logger.Debug("Using git repository", "repo", repoURL)

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
			logger.Debug("Found remote tag", "tag", ref.Name().Short())
		}
	}
	if len(rawTags) == 0 {
		return versionResult{}, fmt.Errorf("no tags found in repository %s", repoURL)
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	tagNames := make([]string, len(rawTags))
	tagHashMap := make(map[string]plumbing.Hash)
	for i, t := range rawTags {
		tagNames[i] = t.Name
		tagHashMap[t.Name] = t.Hash
	}

	best, err := resolveLatestVersion(tagNames, gitMonitor, compiledIgnore, transforms, logger)
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
	commitSHA := ""
	if tagObj, err := object.GetTag(storage, upstreamHash); err == nil {
		if commitObj, err := object.GetCommit(storage, tagObj.Target); err == nil {
			commitSHA = commitObj.Hash.String()
		}
	} else if commitObj, err := object.GetCommit(storage, upstreamHash); err == nil {
		commitSHA = commitObj.Hash.String()
	}

	if commitSHA == "" {
		return versionResult{}, fmt.Errorf("failed to resolve commit for tag %s", best.Upstream)
	}

	return versionResult{
		Version:   best.Transformed,
		CommitSHA: commitSHA,
	}, nil
}

func getLatestReleaseMonitorVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, transforms []compiledVersionTransform) (versionResult, error) {
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

	logger.Debug("Previewing response", "response_preview", truncateString(jsonBody, 200))

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

	var versions []string
	if !cfg.Update.EnablePreReleaseTags {
		versions = project.StableVersions
	} else {
		versions = project.Versions
	}

	if len(versions) == 0 {
		return versionResult{}, fmt.Errorf("no versions found in release-monitor response for project %d", rm.Identifier)
	}

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	best, err := resolveLatestVersion(versions, rm, compiledIgnore, transforms, logger)
	if err != nil {
		return versionResult{}, err
	}

	return versionResult{
		Version:   best.Transformed,
		CommitSHA: "",
	}, nil
}

func getLatestOCIVersion(ctx context.Context, logger *slog.Logger, cfg *config.Configuration, transforms []compiledVersionTransform) (versionResult, error) {
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

	compiledIgnore, err := compileIgnorePatterns(cfg.Update.IgnoreRegexPatterns)
	if err != nil {
		return versionResult{}, fmt.Errorf("compiling ignore patterns: %w", err)
	}

	best, err := resolveLatestVersion(tags, oci, compiledIgnore, transforms, logger)
	if err != nil {
		return versionResult{}, err
	}

	return versionResult{
		Version:   best.Transformed,
		CommitSHA: "",
	}, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

func compileIgnorePatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid ignore pattern regex %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func compileVersionTransforms(vts []config.VersionTransform) ([]compiledVersionTransform, error) {
	out := make([]compiledVersionTransform, 0, len(vts))
	for _, t := range vts {
		re, err := regexp.Compile(t.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid version transform regex %q: %w", t.Match, err)
		}
		out = append(out, compiledVersionTransform{
			Re:      re,
			Replace: t.Replace,
		})
	}
	return out, nil
}

func compareVersions(logger *slog.Logger, currentStr, latestStr string) int {
	current, err := apk.ParseVersion(currentStr)
	if err != nil {
		logger.Warn("Failed to parse current version", "tag", currentStr, "error", err)
		return -1
	}

	latest, err := apk.ParseVersion(latestStr)
	if err != nil {
		logger.Warn("Failed to parse resolved version", "tag", latestStr, "error", err)
		return 1
	}
	return apk.CompareVersions(current, latest)
}

func persistState(ctx context.Context, log *slog.Logger, s3Client *s3.Client, bucket, stateKey string, pkgState packageState, result versionResult, updated bool) {
	pkgState.LastChecked = time.Now()
	if updated {
		pkgState.LastVersion = result.Version
	}

	if err := savePackageState(ctx, s3Client, bucket, stateKey, pkgState); err != nil {
		log.Warn("Failed to persist package state to S3",
			"bucket", bucket,
			"key", stateKey,
			"error", err,
		)
	}
}

func loadPackageState(ctx context.Context, logger *slog.Logger, client *s3.Client, bucket, key string) (packageState, error) {
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
			if apiErr.ErrorCode() == "NoSuchKey" {
				logger.Debug("No existing state found in S3, initializing new state", "key", key)
				return packageState{}, nil
			}
		}
		return packageState{}, fmt.Errorf("fetching state from S3: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

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
	logger *slog.Logger,
	gh *github.Client,
	owner, repo string,
	filePath string,
	pkgName, newVersion string,
	prBranch, prTitle, prBody string,
	sequential bool,
	dryRun bool,
) error {
	log := logger.With(
		"package", pkgName,
		"version", newVersion,
		"branch", prBranch,
	)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	fileAPIPath := strings.TrimPrefix(filePath, "/github/workspace/")
	var existingFile *github.RepositoryContent

	log.Debug("Checking for branch existence")
	_, resp, err := gh.Repositories.GetBranch(ctx, owner, repo, prBranch, 0)
	branchExists := (err == nil)

	branchPRs, _, err := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  fmt.Sprintf("%s:%s", owner, prBranch),
	})
	if err != nil {
		return fmt.Errorf("checking for existing branch PRs: %w", err)
	}
	prExists := len(branchPRs) > 0

	if branchExists {
		remoteFile, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if err == nil {
			existingFile = remoteFile
			remoteContent, _ := remoteFile.GetContent()

			if remoteContent == string(content) && prExists {
				log.Info("Content already matches branch and PR is open, nothing to do")
				return nil
			}
		}

		if sequential {
			log.Info("Sequential mode: branch exists, skipping update")
			return nil
		}
	} else if resp != nil && resp.StatusCode != 404 {
		return fmt.Errorf("github api error fetching branch info (status %d): %w", resp.StatusCode, err)
	}

	prs, _, err := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{State: "open"})
	if err != nil {
		return fmt.Errorf("listing all open PRs: %w", err)
	}

	for _, pr := range prs {
		if strings.HasPrefix(pr.GetTitle(), pkgName+"/") {
			if sequential {
				log.Info("Open PR exists for package, skipping (sequential)")
				return nil
			}
			if pr.GetTitle() != prTitle {
				if dryRun {
					log.Info("DRY RUN: would close outdated PR", "number", pr.GetNumber())
					continue
				}
				log.Info("Closing outdated PR", "number", pr.GetNumber())
				if _, _, err := gh.PullRequests.Edit(ctx, owner, repo, pr.GetNumber(), &github.PullRequest{
					State: github.Ptr("closed"),
				}); err != nil {
					log.Warn("failed to close outdated PR", "number", pr.GetNumber(), "error", err)
				}
			}
		}
	}

	if dryRun {
		return nil
	}

	repoInfo, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("getting repo info: %w", err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()

	ref, _, err := gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
	if err != nil {
		return fmt.Errorf("getting default branch ref: %w", err)
	}
	headSHA := ref.Object.GetSHA()

	if !branchExists {
		_, _, err = gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
			Ref: "refs/heads/" + prBranch,
			SHA: headSHA,
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("creating branch: %w", err)
		}

		remoteFile, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if err != nil {
			return fmt.Errorf("fetching file info from new branch: %w", err)
		}
		existingFile = remoteFile
	}

	_, _, err = gh.Repositories.UpdateFile(ctx, owner, repo, fileAPIPath,
		&github.RepositoryContentFileOptions{
			Message: github.Ptr(prTitle),
			Content: content,
			SHA:     existingFile.SHA,
			Branch:  github.Ptr(prBranch),
		})
	if err != nil {
		return fmt.Errorf("updating file: %w", err)
	}

	if !prExists {
		newPR, _, err := gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
			Title: github.Ptr(prTitle),
			Body:  github.Ptr(prBody),
			Head:  github.Ptr(prBranch),
			Base:  github.Ptr(defaultBranch),
		})
		if err != nil {
			return fmt.Errorf("creating PR: %w", err)
		}

		labels := []string{"automated pr", "request-version-update"}
		_, _, err = gh.Issues.AddLabelsToIssue(ctx, owner, repo, newPR.GetNumber(), labels)
		if err != nil {
			log.Warn("Failed to add labels", "error", err)
		}

		log.Info("PR is ready!", "url", newPR.GetHTMLURL())
	}

	return nil
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

func discoverConfigs(ctx context.Context, logger *slog.Logger) ([]discoveredConfig, error) {
	var found []discoveredConfig
	cwd, _ := os.Getwd()

	err := filepath.WalkDir(cwd, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d.IsDir() && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			cfg, err := config.ParseConfiguration(ctx, path)
			if err == nil {
				if !cfg.Update.Enabled {
					logger.Debug("Skipping config: updates disabled", "package_name", cfg.Package.Name, "path", path)
					return nil
				}
				found = append(found, discoveredConfig{Path: path, Config: cfg})
			}
		}
		return nil
	})
	return found, err
}

func main() {
	logLevelFlag := flag.String("log-level", "info", "Log level")
	dryRunFlag := flag.Bool("dry-run", false, "Do not perform updates or S3 writes")
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	logger.Info("Starting melange-renovator", "version", version, "commit", commitSHA, "build_date", buildDate)
	logger.Info("Runtime Environment",
		"GOOS", runtime.GOOS,
		"GOARCH", runtime.GOARCH,
		"GoVersion", runtime.Version(),
	)

	if !*dryRunFlag {
		if *s3BucketFlag == "" {
			logger.Error("S3 bucket is required in non-dry-run mode", "hint", "set -s3-bucket or use -dry-run")
			os.Exit(1)
		}
		if os.Getenv("GITHUB_TOKEN") == "" {
			logger.Error("GITHUB_TOKEN is required in non-dry-run mode", "hint", "set GITHUB_TOKEN or use -dry-run")
			os.Exit(1)
		}
		if os.Getenv("GITHUB_REPOSITORY") == "" {
			logger.Error("GITHUB_REPOSITORY is required in non-dry-run mode", "hint", "set GITHUB_REPOSITORY or use -dry-run")
			os.Exit(1)
		}
	}

	ctx := context.Background()

	discoveredConfigs, err := discoverConfigs(ctx, logger)
	if err != nil {
		logger.Error("Failed during auto-discovery", "error", err)
		os.Exit(1)
	}

	if len(discoveredConfigs) == 0 {
		logger.Warn("No melange configs were discovered in the current working directory")
		os.Exit(0)
	}

	awsOpts := awsOptions{
		Bucket:    *s3BucketFlag,
		Region:    *awsRegionFlag,
		AccessKey: *awsAccessKeyFlag,
		SecretKey: *awsSecretKeyFlag,
		Endpoint:  *awsEndpointFlag,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(*concurrencyFlag)

	var successCount int64
	var failureCount int64

	for _, item := range discoveredConfigs {
		g.Go(func() error {
			l := logger.With("config", item.Path)
			if err := run(ctx, l, item.Path, item.Config, *dryRunFlag, awsOpts); err != nil {
				l.Error("config processing failed", "error", err)
				atomic.AddInt64(&failureCount, 1)
				return nil
			}
			atomic.AddInt64(&successCount, 1)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		logger.Error("Renovate execution halted due to a fatal error", "error", err)
		os.Exit(1)
	}

	logger.Info("Renovate finished",
		"total", len(discoveredConfigs),
		"succeeded", atomic.LoadInt64(&successCount),
		"failed", atomic.LoadInt64(&failureCount),
	)
}

func run(ctx context.Context, logger *slog.Logger, filePath string, cfg *config.Configuration, dryRun bool, awsOpts awsOptions) error {
	log := logger.With("package_name", cfg.Package.Name, "current_version", cfg.Package.Version)

	if !cfg.Update.Enabled {
		log.Debug("Updates disabled for package, skipping")
		return nil
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
			return fmt.Errorf("loading AWS config: %w", err)
		}

		s3Client = s3.NewFromConfig(awsConfig, func(o *s3.Options) {
			if awsOpts.Endpoint != "" {
				o.BaseEndpoint = aws.String(awsOpts.Endpoint)
			}
		})

		pkgState, err = loadPackageState(ctx, log, s3Client, awsOpts.Bucket, stateKey)
		if err != nil {
			return fmt.Errorf("loading package state from S3: %w", err)
		}

		if !shouldRunSchedule(cfg.Update.Schedule, pkgState.LastChecked) {
			log.Info("Skipping package: not due per schedule",
				"schedule", cfg.Update.Schedule,
				"last_checked", pkgState.LastChecked,
			)
			return nil
		}
	}

	compiledTransforms, err := compileVersionTransforms(cfg.Update.VersionTransform)
	if err != nil {
		return fmt.Errorf("compiling version transforms: %w", err)
	}

	var result versionResult
	switch {
	case cfg.Update.GitHubMonitor != nil:
		result, err = getLatestGitHubVersion(ctx, log, cfg, compiledTransforms)
	case cfg.Update.ReleaseMonitor != nil:
		result, err = getLatestReleaseMonitorVersion(ctx, log, cfg, compiledTransforms)
	case cfg.Update.GitMonitor != nil:
		result, err = getLatestGitVersion(ctx, log, cfg, compiledTransforms)
	case cfg.Update.OCIMonitor != nil:
		result, err = getLatestOCIVersion(ctx, log, cfg, compiledTransforms)
	default:
		return fmt.Errorf("no update monitor configured for package")
	}
	if err != nil {
		return fmt.Errorf("fetching upstream version: %w", err)
	}

	isUpToDate := compareVersions(log, cfg.Package.Version, result.Version) >= 0
	if isUpToDate {
		log.Info("Package is up to date")
		if s3Client != nil {
			persistState(ctx, log, s3Client, awsOpts.Bucket, stateKey, pkgState, result, false)
		}
		return nil
	}

	log.Info("Update is available", "resolved_version", result.Version)

	prBranch := fmt.Sprintf("update-%s", cfg.Package.Name)
	prTitle := fmt.Sprintf("%s/%s package update", cfg.Package.Name, result.Version)
	prBody := fmt.Sprintf("<p align=\"center\">\n" +
		"  <img src=\"https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg\" />\n" +
		"</p>")

	if err := bumpConfig(ctx, filePath, result.Version, result.CommitSHA); err != nil {
		return fmt.Errorf("bumping config: %w", err)
	}

	if dryRun {
		dryRunPath := filePath + ".dry-run"
		content := fmt.Sprintf("BRANCH: %s\nTITLE: %s\nBODY: %s\n", prBranch, prTitle, prBody)
		if err := os.WriteFile(dryRunPath, []byte(content), 0644); err != nil {
			log.Warn("Failed to write dry-run artifact", "path", dryRunPath, "error", err)
		} else {
			log.Info("DRY RUN: wrote PR metadata to disk", "path", dryRunPath)
		}
		return nil
	}

	repoEnv := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(repoEnv, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid GITHUB_REPOSITORY format %q: expected owner/repo", repoEnv)
	}

	ghClient := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	if err := ensurePR(ctx, log, ghClient, parts[0], parts[1],
		filePath, cfg.Package.Name, result.Version,
		prBranch, prTitle, prBody,
		cfg.Update.RequireSequential, dryRun,
	); err != nil {
		return fmt.Errorf("ensuring pull request: %w", err)
	}

	log.Info("Package updated successfully", "upstream_version", result.Version)
	persistState(ctx, log, s3Client, awsOpts.Bucket, stateKey, pkgState, result, true)
	return nil
}
