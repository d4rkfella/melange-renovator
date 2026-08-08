package renovator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/bump"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
	"golang.org/x/sync/errgroup"
)

func bumpConfig(ctx context.Context, configPath, newVersion, expectedCommit string) error {
	if err := trimTrailingWhitespace(configPath); err != nil {
		return fmt.Errorf("trimming trailing whitespace: %w", err)
	}

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

func trimTrailingWhitespace(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func discoverConfigs(
	ctx context.Context,
	root string,
	configFilePatterns []string,
	ignorePaths []string,
) ([]discoveredConfig, error) {
	log := clog.FromContext(ctx)

	var found []discoveredConfig

	var patterns []*regexp.Regexp
	for _, pattern := range configFilePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid config file pattern %q: %w", pattern, err)
		}
		log.Debug(
			"Using file pattern for melange config discovery",
			"pattern", pattern,
		)
		patterns = append(patterns, re)
	}

	var matchedPaths []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Warn(
				"directory walk error",
				"path", path,
				"error", err,
			)
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			log.Warn(
				"failed calculating relative path",
				"path", path,
				"error", err,
			)
			return nil
		}

		if shouldIgnorePath(relPath, ignorePaths) {
			if d.IsDir() {
				log.Debug(
					"skipping ignored directory",
					"path", relPath,
				)
				return filepath.SkipDir
			}

			log.Debug(
				"skipping ignored file",
				"path", relPath,
			)
			return nil
		}

		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if !matchesConfigPattern(relPath, patterns) {
			return nil
		}

		matchedPaths = append(matchedPaths, relPath)

		cfg, err := config.ParseConfiguration(ctx, path)
		if err != nil {
			log.Debug(
				"Failed to parse configuration file",
				"path", relPath,
				"error", err,
			)
			return nil
		}

		if !cfg.Update.Enabled {
			log.Debug(
				"skipping config: updates are disabled",
				"path", path,
			)
			return nil
		}

		found = append(found, discoveredConfig{
			File:   packageFile{Path: path, RepoAPIPath: filepath.ToSlash(relPath)},
			Config: cfg,
		})

		return nil
	})

	log.Debug(
		fmt.Sprintf(
			"Matched %d file(s): %s",
			len(matchedPaths),
			strings.Join(matchedPaths, ", "),
		),
	)

	return found, err
}

func matchesConfigPattern(path string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func shouldIgnorePath(path string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// RunContext executes the melange-renovator workflow using the typed command options.
func RunContext(ctx context.Context, opts Options) {
	log := clog.FromContext(ctx)

	ghClient := github.NewClient(nil).WithAuthToken(opts.Token)

	bot, err := detectBotLogin(ctx, ghClient)
	if err != nil {
		log.Error("failed to detect bot identity", "error", err)
		os.Exit(1)
	}

	var m mutator
	if opts.DryRun {
		m = newDryRunMutator()
	} else {
		m = newLiveMutator(ghClient)
	}

	var optFns []func(*awscfg.LoadOptions) error
	if opts.AWSRegion != "" {
		optFns = append(optFns, awscfg.WithRegion(opts.AWSRegion))
	}
	if opts.AWSAccessKey != "" && opts.AWSSecretKey != "" {
		creds := credentials.NewStaticCredentialsProvider(opts.AWSAccessKey, opts.AWSSecretKey, "")
		optFns = append(optFns, awscfg.WithCredentialsProvider(creds))
	}

	awsConfig, err := awscfg.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		log.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	s3Client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		if opts.AWSEndpoint != "" {
			o.BaseEndpoint = aws.String(opts.AWSEndpoint)
		}
	})

	if !opts.Autodiscover {
		repoParts := strings.SplitN(os.Getenv("GITHUB_REPOSITORY"), "/", 2)
		if len(repoParts) != 2 {
			log.Error("invalid GITHUB_REPOSITORY format, expected owner/repo", "value", os.Getenv("GITHUB_REPOSITORY"))
			os.Exit(1)
		}
		cwd, err := os.Getwd()
		if err != nil {
			log.Error("failed to get working directory", "error", err)
			os.Exit(1)
		}
		processRepo(ctx, ghClient, m, s3Client, repoParts[0], repoParts[1], cwd, opts, bot)
		return
	}

	log.Debug("Autodiscovering GitHub repositories")
	allRepos, err := listInstallationRepos(ctx, ghClient)
	if err != nil {
		log.Error("failed to autodiscover repositories", "error", err)
		os.Exit(1)
	}
	log.Debug(fmt.Sprintf("Autodiscovered %d repositories", len(allRepos)))

	log.Debug("Applying autodiscoverFilter", "autodiscoverFilter", opts.AutodiscoverFilter)
	matched := filterRepos(allRepos, opts.AutodiscoverFilter)
	log.Info("Autodiscovered repositories", "length", len(matched), "repositories", func() []string {
		names := make([]string, len(matched))
		for i, r := range matched {
			names[i] = r.GetFullName()
		}
		return names
	}())

	for _, repo := range matched {
		repoLog := log.With("repository", repo.GetFullName())

		dir, err := prepareRepo(clog.WithLogger(ctx, repoLog), repo, opts.Token, opts.BaseDir)
		if err != nil {
			repoLog.Error("failed to prepare repository clone, skipping", "error", err)
			continue
		}

		processRepo(clog.WithLogger(ctx, repoLog), ghClient, m, s3Client,
			repo.GetOwner().GetLogin(), repo.GetName(), dir, opts, bot)
	}
}

// processRepo runs discovery, per-package processing, and the dependency
// dashboard update for a single repository rooted at rootDir.
func processRepo(ctx context.Context, ghClient *github.Client, m mutator, s3Client *s3.Client, repoOwner, repoName, rootDir string, opts Options, bot string) {
	log := clog.FromContext(ctx)

	discoveredConfigs, err := discoverConfigs(
		ctx,
		rootDir,
		opts.ConfigFilePatterns,
		opts.IgnorePaths,
	)
	if err != nil {
		log.Error("Melange-renovator failed during auto-discovery", "error", err)
		return
	}

	if len(discoveredConfigs) == 0 {
		log.Warn("No valid melange configs were discovered")
		return
	}

	awsOpts := awsOptions{
		Bucket:    opts.S3Bucket,
		Region:    opts.AWSRegion,
		AccessKey: opts.AWSAccessKey,
		SecretKey: opts.AWSSecretKey,
		Endpoint:  opts.AWSEndpoint,
	}

	rm := newRepoManager(ghClient, repoOwner, repoName, m)

	defaultBranch := rm.getDefaultBranch(ctx)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(opts.Concurrency)

	var successCount, failureCount atomic.Int64
	var reportMu sync.Mutex
	var report []renovatePackageFile

	_, dashboardStartBody, checks, err := rm.readDashboard(ctx)
	if err != nil {
		log.Warn("failed to read dependency dashboard, proceeding without forced actions", "error", err)
	}

	runCfg := runtimeConfig{
		RecreateWhen: opts.RecreateWhen,
		RebaseWhen:   opts.RebaseWhen,
		Bot:          bot,
		DashboardActions: dashboardActions{
			RebasePR:    checks.RebasePR,
			RebaseAll:   checks.RebaseAll,
			RecreatePR:  checks.RecreatePR,
			RecreateAll: checks.RecreateAll,
		},
	}

	for _, item := range discoveredConfigs {
		g.Go(func() error {
			dep, err := processConfig(gctx, ghClient, rm, s3Client, item.File, item.Config, opts.DryRun, awsOpts, runCfg, repoOwner, repoName, defaultBranch)
			if err != nil {
				clog.FromContext(gctx).Error("error processing melange config", "error", err, "config_path", item.File.Path)
				failureCount.Add(1)
				if dep == nil {
					dep = &renovateDep{
						DepName:     item.Config.Package.Name,
						PackageName: item.Config.Package.Name,
						Monitor:     buildMonitorConfig(item.Config),
						Skipped:     true,
						SkipReason:  err.Error(),
						Warnings:    []string{},
					}
				}
			} else {
				successCount.Add(1)
			}

			reportMu.Lock()
			report = append(report, renovatePackageFile{
				PackageFile: item.File.RepoAPIPath,
				Deps:        []renovateDep{*dep},
			})
			reportMu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		log.Error("Melange-renovator execution halted due to a fatal error", "error", err)
		return
	}

	log.Info("Melange-renovator finished processing repository",
		"total", len(discoveredConfigs),
		"succeeded", successCount.Load(),
		"failed", failureCount.Load(),
	)

	if err := rm.ensureDependencyDashboard(ctx, report, false, dashboardStartBody); err != nil {
		log.Warn("failed to update dependency dashboard", "error", err)
	}

	sort.Slice(report, func(i, j int) bool {
		return report[i].PackageFile < report[j].PackageFile
	})

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error("failed to marshal JSON report", "error", err)
		return
	}

	fmt.Println(string(data))
}

func processConfig(ctx context.Context, ghClient *github.Client, rm *repoManager, s3Client *s3.Client, file packageFile, cfg *config.Configuration, dryRun bool, awsOpts awsOptions, runCfg runtimeConfig, repoOwner string, repoName string, defaultBranch string) (*renovateDep, error) {
	ctx = clog.WithLogger(ctx, clog.FromContext(ctx).With(
		"package_name", cfg.Package.Name,
		"current_version", cfg.Package.Version,
		"config_path", file.RepoAPIPath,
	))
	log := clog.FromContext(ctx)

	dep := &renovateDep{
		DepName:        cfg.Package.Name,
		PackageName:    cfg.Package.Name,
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

	stateKey := fmt.Sprintf("state/%s/%s/%s.json", repoOwner, repoName, cfg.Package.Name)

	pkgState, err := loadPackageState(ctx, s3Client, awsOpts.Bucket, stateKey)
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
		return dep, nil
	}

	var result versionResult
	switch {
	case cfg.Update.GitHubMonitor != nil:
		result, err = getLatestGitHubVersion(ctx, ghClient, cfg, patterns)
	case cfg.Update.ReleaseMonitor != nil:
		result, err = getLatestReleaseMonitorVersion(ctx, cfg, patterns)
	case cfg.Update.GitMonitor != nil:
		result, err = getLatestGitVersion(ctx, cfg, patterns)
	case cfg.Update.OCIMonitor != nil:
		result, err = getLatestOCIVersion(ctx, cfg, patterns)
	case cfg.Update.VersionDataMonitor != nil:
		dep.Skipped = true
		dep.SkipReason = "version-data monitor is not yet implemented"
		return dep, fmt.Errorf("version-data monitor is not supported")
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
		dep.UpdateAvailable = false
		persistState(ctx, rm.mutator, s3Client, awsOpts.Bucket, stateKey, pkgState, result, false)
		return dep, nil
	}

	dep.UpdateAvailable = true

	if err := bumpConfig(ctx, file.Path, result.Version, result.CommitSHA); err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return dep, fmt.Errorf("bumping config: %w", err)
	}

	outcome, err := rm.ensurePR(ctx, file, cfg.Package.Name, result, cfg.Update.RequireSequential, runCfg, defaultBranch)
	if err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return dep, err
	}
	dep.PRUrl = outcome.URL
	dep.BlockedByClosedPR = outcome.BlockedByClosedPR
	dep.ClosedPRUrl = outcome.ClosedPRUrl
	if len(outcome.ClosedSuperseded) > 0 {
		numbers := make([]string, len(outcome.ClosedSuperseded))
		for i, n := range outcome.ClosedSuperseded {
			numbers[i] = fmt.Sprintf("#%d", n)
		}
		dep.Warnings = append(dep.Warnings, fmt.Sprintf(
			"closed superseded PR(s) %s in favor of this update", strings.Join(numbers, ", ")))
	}
	persistState(ctx, rm.mutator, s3Client, awsOpts.Bucket, stateKey, pkgState, result, true)
	return dep, nil
}
