package renovator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
	"golang.org/x/sync/errgroup"
)

type Options struct {
	LogLevel     string
	DryRun       bool
	Concurrency  int
	S3Bucket     string
	AWSRegion    string
	AWSAccessKey string
	AWSSecretKey string
	AWSEndpoint  string
	Token        string
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

func Run(opts Options) {
	RunContext(context.Background(), opts)
}

func RunContext(ctx context.Context, opts Options) {
	log := clog.FromContext(ctx)

	if !opts.DryRun {
		if opts.S3Bucket == "" {
			log.Error("S3 bucket is required in non-dry-run mode", "hint", "set -s3-bucket or use -dry-run")
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
		Bucket:    opts.S3Bucket,
		Region:    opts.AWSRegion,
		AccessKey: opts.AWSAccessKey,
		SecretKey: opts.AWSSecretKey,
		Endpoint:  opts.AWSEndpoint,
	}

	baseCtx := ctx
	g, ctx := errgroup.WithContext(baseCtx)
	g.SetLimit(opts.Concurrency)

	var successCount atomic.Int64
	var failureCount atomic.Int64

	var reportMu sync.Mutex
	var report []renovatePackageFile

	var checks dashboardChecks
	var dashboardStartBody string
	var ghForDashboard *github.Client
	var repoOwner, repoName string
	if !opts.DryRun {
		ghForDashboard = github.NewClient(nil).WithAuthToken(opts.Token)
		repoParts := strings.SplitN(os.Getenv("GITHUB_REPOSITORY"), "/", 2)
		if len(repoParts) != 2 {
			log.Error("invalid GITHUB_REPOSITORY format, expected owner/repo", "value", os.Getenv("GITHUB_REPOSITORY"))
			os.Exit(1)
		}
		repoOwner, repoName = repoParts[0], repoParts[1]
		_, dashboardStartBody, checks, err = readDashboard(baseCtx, ghForDashboard, repoOwner, repoName)
		if err != nil {
			log.Warn("failed to read dependency dashboard, proceeding without forced actions", "error", err)
		}
	}

	for _, item := range discoveredConfigs {
		g.Go(func() error {
			dep, err := run(ctx, item.Path, item.Config, opts.DryRun, awsOpts, checks)
			if err != nil {
				clog.FromContext(ctx).Error("error processing melange config", "error", err, "config_path", item.Path)
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

	if !opts.DryRun {
		if err := ensureDependencyDashboard(baseCtx, ghForDashboard, repoOwner, repoName, report, opts.DryRun, false, dashboardStartBody); err != nil {
			log.Warn("failed to update dependency dashboard", "error", err)
		}
	}

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

func run(ctx context.Context, filePath string, cfg *config.Configuration, dryRun bool, awsOpts awsOptions, checks dashboardChecks) (*renovateDep, error) {
	ctx = clog.WithLogger(ctx, clog.FromContext(ctx).With(
		"package_name", cfg.Package.Name,
		"current_version", cfg.Package.Version,
		"config_path", filePath,
	))
	log := clog.FromContext(ctx)

	forceRebase := checks.ShouldForce(cfg.Package.Name)

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

		if !shouldRunSchedule(cfg.Update.Schedule, pkgState.LastChecked) && !forceRebase {
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
		"</p>" + prRebaseControl

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
		filePath, cfg.Package.Name, result,
		prBranch, prTitle, prBody,
		cfg.Update.RequireSequential, dryRun,
		forceRebase,
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
