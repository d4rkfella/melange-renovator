package app

import (
	"context"
	"time"

	"github.com/d4rkfella/melange-renovator/internal/dashboard"
	"github.com/d4rkfella/melange-renovator/internal/repo"
	"github.com/d4rkfella/melange-renovator/internal/report"
)

// ConfigFile is a single discovered melange package configuration.
type ConfigFile struct {
	// Path is the absolute local filesystem path, used to read and bump
	// the file's contents.
	Path string
	// RepoRelPath is the path relative to the repository root, used as the
	// GitHub Contents API path and reported in the JSON output.
	RepoRelPath string
}

// Discoverer finds repositories to operate on in autodiscover mode (as
// opposed to the single pre-checked-out repo used in normal GitHub Actions
// mode).
type Discoverer interface {
	// ListRepos returns every repository the tool should process, already
	// filtered by the configured autodiscover patterns.
	ListRepos(ctx context.Context) ([]repo.Identifier, error)

	// PrepareLocal ensures repo has a local, up-to-date working copy under
	// baseDir and returns that directory.
	PrepareLocal(ctx context.Context, repo repo.Identifier, baseDir string) (dir string, err error)
}

type RenovatorConfig struct {
	DashboardTitle     *string
	RebaseWhen         *RebasePolicy
	RecreateWhen       *RecreatePolicy
	ConfigFilePatterns []string
	IgnorePaths        []string
}

// RenovatorConfigLoader loads repository-level overrides, analogous to upstream
// Renovate reading renovate.json from the repo it's processing. A repo
// with no config file returns a zero RepoConfig and a nil error — that's
// not a failure, just "use the global defaults for everything."
type RenovatorConfigLoader interface {
	Load(ctx context.Context, root string) (RenovatorConfig, error)
}

// ConfigScanner walks a local repository checkout and returns every
// melange package config eligible for an update check.
type ConfigScanner interface {
	Scan(ctx context.Context, root string, filePatterns, ignorePaths []string) ([]ConfigFile, error)
}

// RepoInspector resolves repository-level facts needed before any package
// within it can be processed.
type RepoInspector interface {
	DefaultBranch(ctx context.Context, repo repo.Identifier) (string, error)
}

// IdentityResolver reports the GitHub login melange-renovator is currently
// authenticated as, so it can recognize its own past commits and treat
// anything else on a PR branch as a human edit.
type IdentityResolver interface {
	BotLogin(ctx context.Context) (string, error)
}

// DashboardManager owns the "Renovate Dashboard" issue lifecycle for a repo.
type DashboardManager interface {
	// Read returns any manual actions requested via dashboard checkboxes
	// since the last run, plus the issue body as it stood at the start of
	// this run (used later to preserve mid-run checkbox changes).
	Read(ctx context.Context, repo repo.Identifier, title, bot string) (actions dashboard.Actions, startBody string, err error)

	// Reconcile creates, updates, or closes the dashboard issue based on
	// this run's final report.
	Reconcile(ctx context.Context, repo repo.Identifier, title, bot string, packages []report.PackageFile, startBody string) error
}

// RepoContext carries the per-run, per-repository facts every package's
// processing needs, so PackageProcessor doesn't take a fistful of
// parameters for values that never vary within one repo run.
type RepoContext struct {
	Repo             repo.Identifier
	DefaultBranch    string
	Bot              string
	DashboardActions dashboard.Actions
	RebaseWhen       RebasePolicy
	RecreateWhen     RecreatePolicy
	DryRun           bool
}

// PackageProcessor resolves the latest upstream version for one package,
// bumps its config, and reconciles the corresponding pull request. It never
// returns an error: a single package failing is reported via
// Dep.Skipped/Dep.SkipReason rather than aborting the run, matching the
// original tool's behavior of always producing a complete report.
type PackageProcessor interface {
	Process(ctx context.Context, rc RepoContext, file ConfigFile) report.Dep
}

// Clock is injected wherever wall-clock time affects a decision (schedule
// checks, state timestamps), so tests can control it instead of depending
// on time.Now directly.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock, backed by time.Now.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
