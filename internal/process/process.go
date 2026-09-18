// Package process implements app.PackageProcessor: for one package config,
// it resolves the latest upstream version (internal/versioning), bumps the
// config, reconciles the pull request (internal/ghrepo), and persists
// check state (internal/state).
package process

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/renovate/bump"
	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/app"
	"github.com/d4rkfella/melange-renovator/internal/ghrepo"
	"github.com/d4rkfella/melange-renovator/internal/report"
	"github.com/d4rkfella/melange-renovator/internal/state"
	"github.com/d4rkfella/melange-renovator/internal/versioning"
)

// Processor implements app.PackageProcessor.
type Processor struct {
	GitHubAPI      ghrepo.GitHubAPI // shared across repos: used for tag listing and per-repo ghrepo.Client construction
	GitSources     versioning.GitRemote
	OCISources     versioning.OCITagLister
	ReleaseSources versioning.ReleaseMonitorFetcher
	State          state.Store
	DryRun         bool
	Clock          app.Clock
}

func (p *Processor) Process(ctx context.Context, rc app.RepoContext, file app.ConfigFile) report.Dep {
	log := clog.FromContext(ctx)

	cfg, err := config.ParseConfiguration(ctx, file.Path)
	if err != nil {
		return report.Dep{
			DepName: file.RepoRelPath, PackageName: file.RepoRelPath,
			Skipped: true, SkipReason: fmt.Sprintf("parsing config: %v", err), Warnings: []string{},
		}
	}

	ctx = clog.WithLogger(ctx, log.With(
		"package_name", cfg.Package.Name, "current_version", cfg.Package.Version, "config_path", file.RepoRelPath))
	log = clog.FromContext(ctx)

	dep := report.Dep{
		DepName: cfg.Package.Name, PackageName: cfg.Package.Name,
		Monitor: versioning.BuildMonitorReport(cfg), CurrentVersion: cfg.Package.Version,
		Warnings: []string{}, DryRun: p.DryRun,
	}
	if cfg.Update.Schedule != nil {
		dep.Schedule = &report.Schedule{Period: string(cfg.Update.Schedule.Period), Reason: cfg.Update.Schedule.Reason}
	}

	patterns, err := versioning.CompilePatterns(cfg)
	if err != nil {
		return skip(dep, log, err.Error())
	}

	stateKey := state.Key(rc.Repo.Owner, rc.Repo.Name, cfg.Package.Name)
	pkgState, err := p.State.Load(ctx, stateKey)
	if err != nil {
		return skip(dep, log, err.Error())
	}

	forceRetry := rc.DashboardActions.RetryAll || rc.DashboardActions.RetryPackage[cfg.Package.Name]
	if !forceRetry && !shouldRunSchedule(p.Clock.Now(), cfg.Update.Schedule, pkgState.LastChecked) {
		dep.Skipped, dep.SkipReason = true, "not due per schedule"
		return dep
	}

	resolver, err := versioning.NewResolver(cfg, versioning.Sources{
		GitHub:         ghrepo.NewTagSource(p.GitHubAPI),
		Git:            p.GitSources,
		OCI:            p.OCISources,
		ReleaseMonitor: p.ReleaseSources,
	})
	if err != nil {
		return skip(dep, log, err.Error())
	}

	result, err := resolver.Resolve(ctx, patterns)
	if err != nil {
		return skip(dep, log, err.Error())
	}

	dep.ResolvedTag = result.UpstreamTag
	dep.ResolvedVersion = result.Version
	dep.ResolvedCommit = result.CommitSHA
	if result.TagsSkipped > 0 {
		dep.Warnings = append(dep.Warnings, fmt.Sprintf(
			"%d of %d upstream versions were filtered out by prefix/contains/ignore-regex rules or failed APK version parsing (run with -log-level=debug for details)",
			result.TagsSkipped, result.TagsConsidered))
	}

	if versioning.Compare(ctx, cfg.Package.Version, result.Version) >= 0 {
		dep.UpdateAvailable = false
		p.persist(ctx, stateKey, pkgState, result, false)
		return dep
	}
	dep.UpdateAvailable = true

	if err := bumpConfig(ctx, file.Path, result.Version, result.CommitSHA); err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return skip(dep, log, fmt.Sprintf("bumping config: %v", err))
	}

	content, err := os.ReadFile(file.Path)
	if err != nil {
		return skip(dep, log, fmt.Sprintf("reading bumped config: %v", err))
	}

	client := ghrepo.NewClient(p.GitHubAPI, rc.Repo.Owner, rc.Repo.Name, p.DryRun)
	outcome, err := (&ghrepo.Reconciler{Client: client}).Reconcile(ctx, ghrepo.Input{
		PackageName:      cfg.Package.Name,
		RepoAPIPath:      file.RepoRelPath,
		Content:          content,
		Version:          result.Version,
		DefaultBranch:    rc.DefaultBranch,
		Bot:              rc.Bot,
		Sequential:       cfg.Update.RequireSequential,
		RebaseWhen:       string(rc.RebaseWhen),
		RecreateWhen:     string(rc.RecreateWhen),
		DashboardActions: rc.DashboardActions,
	})
	if err != nil {
		dep.Warnings = append(dep.Warnings, err.Error())
		return skip(dep, log, err.Error())
	}

	dep.PRURL = outcome.PRURL
	dep.ClosedPRURL = outcome.BlockedPRURL
	if len(outcome.SupersededPRs) > 0 {
		numbers := make([]string, len(outcome.SupersededPRs))
		for i, n := range outcome.SupersededPRs {
			numbers[i] = fmt.Sprintf("#%d", n)
		}
		dep.Warnings = append(dep.Warnings, fmt.Sprintf(
			"closed superseded PR(s) %s in favor of this update", strings.Join(numbers, ", ")))
	}

	p.persist(ctx, stateKey, pkgState, result, true)
	return dep
}

func skip(dep report.Dep, log *clog.Logger, reason string) report.Dep {
	log.Warn("skipping package", "reason", reason)
	dep.Skipped, dep.SkipReason = true, reason
	return dep
}

func (p *Processor) persist(ctx context.Context, key string, prior state.State, result versioning.Result, updated bool) {
	st := state.State{LastChecked: p.Clock.Now(), LastVersion: prior.LastVersion}
	if updated {
		st.LastVersion = result.Version
	}
	if err := p.State.Save(ctx, key, st); err != nil {
		clog.FromContext(ctx).Warn("failed to persist package state", "key", key, "error", err)
	}
}

// shouldRunSchedule reports whether a package's update check is due. Moved
// here from the original dashboard.go — it's about per-package check
// scheduling, not the dashboard issue, and now takes now as a parameter
// (via app.Clock) instead of calling time.Now() directly, so it's testable
// with a fixed clock.
func shouldRunSchedule(now time.Time, s *config.Schedule, lastChecked time.Time) bool {
	if s == nil {
		return true
	}
	switch strings.ToLower(string(s.Period)) {
	case "", "none":
		return true
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

func bumpConfig(ctx context.Context, configPath, newVersion, expectedCommit string) error {
	if err := trimTrailingWhitespace(configPath); err != nil {
		return fmt.Errorf("trimming trailing whitespace: %w", err)
	}
	rc, err := renovate.New(renovate.WithConfig(configPath))
	if err != nil {
		return fmt.Errorf("creating renovate client: %w", err)
	}
	ren := bump.New(ctx, bump.WithTargetVersion(newVersion), bump.WithExpectedCommit(expectedCommit))
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
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}
