package app

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/dashboard"
	"github.com/d4rkfella/melange-renovator/internal/repo"
	"github.com/d4rkfella/melange-renovator/internal/report"
	"golang.org/x/sync/errgroup"
)

// Runner orchestrates one full melange-renovator run. It holds no
// package-level state and performs no process exit — every dependency is
// injected via the fields below, and Run reports failure through its
// return value so callers (cmd/melange-renovator, or tests) decide what to
// do about it.
type Runner struct {
	Discoverer            Discoverer
	Scanner               ConfigScanner
	Inspector             RepoInspector
	Identity              IdentityResolver
	Dashboard             DashboardManager
	Processor             PackageProcessor
	RenovatorConfigLoader RenovatorConfigLoader
	Clock                 Clock

	Options Options
}

// Report is the result of a full run, across every repository processed.
type Report struct {
	Repos []RepoReport
}

// RepoReport is the result of processing a single repository.
type RepoReport struct {
	Repo     repo.Identifier
	Packages []report.PackageFile
}

// Run executes one full pass: against every autodiscovered repository when
// Options.Autodiscover is set, or against the single repository already
// checked out at the current working directory otherwise.
func (r *Runner) Run(ctx context.Context) (Report, error) {
	bot, err := r.Identity.BotLogin(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("detecting bot identity: %w", err)
	}

	if !r.Options.Autodiscover {
		repo, err := repoFromEnv()
		if err != nil {
			return Report{}, err
		}
		cwd, err := os.Getwd()
		if err != nil {
			return Report{}, fmt.Errorf("getting working directory: %w", err)
		}
		rep, err := r.runRepo(ctx, repo, cwd, bot)
		if err != nil {
			return Report{}, err
		}
		return Report{Repos: []RepoReport{rep}}, nil
	}

	return r.runAutodiscover(ctx, bot)
}

func (r *Runner) runAutodiscover(ctx context.Context, bot string) (Report, error) {
	log := clog.FromContext(ctx)

	repos, err := r.Discoverer.ListRepos(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("autodiscovering repositories: %w", err)
	}
	log.Info("autodiscovered repositories", "count", len(repos))

	var full Report
	for _, repo := range repos {
		if ctx.Err() != nil {
			log.Warn("context cancelled, stopping autodiscover loop", "error", ctx.Err())
			break
		}

		dir, err := r.Discoverer.PrepareLocal(ctx, repo, r.Options.BaseDir)
		if err != nil {
			log.Error("failed to prepare repository clone, skipping", "repo", repo.FullName(), "error", err)
			continue
		}

		rep, err := r.runRepo(ctx, repo, dir, bot)
		if err != nil {
			log.Error("failed processing repository, skipping", "repo", repo.FullName(), "error", err)
			continue
		}
		full.Repos = append(full.Repos, rep)
	}
	return full, nil
}

func (r *Runner) runRepo(ctx context.Context, repo repo.Identifier, rootDir, bot string) (RepoReport, error) {
	log := clog.FromContext(ctx).With("repository", repo.FullName())
	ctx = clog.WithLogger(ctx, log)

	renovatorCfg, err := r.RenovatorConfigLoader.Load(ctx, rootDir)
	if err != nil {
		log.Warn("failed to load repository config, falling back to global defaults", "error", err)
		renovatorCfg = RenovatorConfig{}
	}

	dashboardTitle := r.Options.DashboardTitle
	if renovatorCfg.DashboardTitle != nil {
		dashboardTitle = *renovatorCfg.DashboardTitle
	}
	filePatterns := r.Options.ConfigFilePatterns
	if len(renovatorCfg.ConfigFilePatterns) > 0 {
		filePatterns = renovatorCfg.ConfigFilePatterns
	}
	ignorePaths := r.Options.IgnorePaths
	if len(renovatorCfg.IgnorePaths) > 0 {
		ignorePaths = renovatorCfg.IgnorePaths
	}
	rebaseWhen := r.Options.RebaseWhen
	if renovatorCfg.RebaseWhen != nil {
		rebaseWhen = *renovatorCfg.RebaseWhen
	}
	recreateWhen := r.Options.RecreateWhen
	if renovatorCfg.RecreateWhen != nil {
		recreateWhen = *renovatorCfg.RecreateWhen
	}

	files, err := r.Scanner.Scan(ctx, rootDir, filePatterns, ignorePaths)
	if err != nil {
		return RepoReport{}, fmt.Errorf("scanning for package configs: %w", err)
	}
	if len(files) == 0 {
		log.Warn("no melange configs discovered")
		return RepoReport{Repo: repo}, nil
	}

	defaultBranch, err := r.Inspector.DefaultBranch(ctx, repo)
	if err != nil {
		log.Warn("failed to resolve default branch, assuming main", "error", err)
		defaultBranch = "main"
	}

	existingIssue, err := r.Dashboard.FindOpen(ctx, repo, dashboardTitle, bot)
	if err != nil {
		log.Warn("failed to fetch dependency dashboard issue", "error", err)
	}

	// 2. Parse actions if an issue exists
	var actions dashboard.Actions
	if existingIssue != nil {
		actions = dashboard.ParseActions(existingIssue.Body)
	}

	rc := RepoContext{
		Repo:             repo,
		DefaultBranch:    defaultBranch,
		Bot:              bot,
		DashboardActions: actions,
		RebaseWhen:       rebaseWhen,
		RecreateWhen:     recreateWhen,
		DryRun:           r.Options.DryRun,
	}

	deps := make([]report.Dep, len(files))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(r.Options.Concurrency)
	for i, file := range files {
		g.Go(func() error {
			deps[i] = r.Processor.Process(gctx, rc, file)
			return nil
		})
	}
	_ = g.Wait() // PackageProcessor never returns an error; see its doc comment.

	packages := make([]report.PackageFile, len(files))
	for i, file := range files {
		packages[i] = report.PackageFile{
			PackageFile: file.RepoRelPath,
			Deps:        []report.Dep{deps[i]},
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].PackageFile < packages[j].PackageFile
	})

	succeeded, failed := 0, 0
	for _, d := range deps {
		if d.Skipped && d.SkipReason != "" && d.SkipReason != "not due per schedule" {
			failed++
		} else {
			succeeded++
		}
	}
	log.Info("finished processing repository", "total", len(files), "succeeded", succeeded, "failed", failed)

	if err := r.Dashboard.Reconcile(ctx, repo, dashboardTitle, bot, packages, existingIssue); err != nil {
		log.Warn("failed to update dependency dashboard", "error", err)
	}

	return RepoReport{Repo: repo, Packages: packages}, nil
}

func repoFromEnv() (repo.Identifier, error) {
	full := os.Getenv("GITHUB_REPOSITORY")
	owner, name, ok := strings.Cut(full, "/")
	if !ok || owner == "" || name == "" {
		return repo.Identifier{}, fmt.Errorf("invalid GITHUB_REPOSITORY %q: expected owner/repo", full)
	}
	return repo.Identifier{Owner: owner, Name: name}, nil
}
