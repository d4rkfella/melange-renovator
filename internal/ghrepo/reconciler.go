package ghrepo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/dashboard"
	"github.com/d4rkfella/melange-renovator/internal/versioning"
)

// Reconciler reconciles a single package's pull request against its
// resolved upstream version. It depends only on the Client interface, so
// its logic is fully testable against a fake — no real GitHub API and no
// dry-run branch needed in tests, since dry-run is just another Client.
type Reconciler struct {
	Client Client
}

// Outcome is the result of reconciling one package's PR.
type Outcome struct {
	PRURL         string // active (open) PR's URL; empty if none exists
	SupersededPRs []int  // numbers of other PRs closed as a result of this run
	BlockedPRURL  string // URL of a closed PR blocking a new one; empty if not blocked
}

// Input groups everything Reconcile needs about the package being updated.
// Content is already-bumped file content — Reconciler never reads the
// local filesystem or knows about melange config bumping; that stays in
// internal/process.
type Input struct {
	PackageName      string
	RepoAPIPath      string // path relative to repo root, as used by the Contents API
	Content          []byte
	Version          string // resolved, transformed upstream version
	DefaultBranch    string
	Bot              string
	Sequential       bool // true when concurrency=1 — affects auto-recreate/supersede behavior
	RebaseWhen       string
	RecreateWhen     string
	DashboardActions dashboard.Actions
}

func (r *Reconciler) Reconcile(ctx context.Context, in Input) (Outcome, error) {
	log := clog.FromContext(ctx)
	branch, title, body := buildPRMetadata(in.PackageName, in.Version)

	branchExists, err := r.Client.BranchExists(ctx, branch)
	if err != nil {
		return Outcome{}, fmt.Errorf("checking branch existence: %w", err)
	}
	openPR, err := r.Client.FindOpenPR(ctx, branch)
	if err != nil {
		return Outcome{}, fmt.Errorf("checking for existing branch PR: %w", err)
	}

	if openPR == nil {
		reopened, blocked, err := r.reopenClosedPRIfAllowed(ctx, branch, in)
		if err != nil {
			return Outcome{}, err
		}
		if blocked != nil {
			return Outcome{BlockedPRURL: blocked.HTMLURL}, nil
		}
		openPR = reopened
	}

	prURL := ""
	rebased := false

	if openPR != nil {
		r.retargetBaseIfDrifted(ctx, openPR, in.DefaultBranch)
		prURL = openPR.HTMLURL

		closed, err := r.closeIfAlreadyOnDefaultBranch(ctx, branch, openPR, in)
		if err != nil {
			return Outcome{}, err
		}
		if closed {
			return Outcome{SupersededPRs: []int{openPR.Number}}, nil
		}

		rebaseNeeded := r.computeRebaseDecision(ctx, branch, openPR, in)

		upToDate, err := r.branchContentUpToDate(ctx, branch, openPR.Title, title, in.RepoAPIPath, in.Content)
		if err != nil {
			return Outcome{}, err
		}
		if upToDate && !rebaseNeeded {
			log.Debug("content and title unchanged and branch up to date, nothing to do")
			return Outcome{PRURL: prURL}, nil
		}

		if rebaseNeeded {
			if err := r.executeRebase(ctx, branch, title, in, openPR); err != nil {
				return Outcome{}, err
			}
			rebased = true
		}
	}

	prExists := openPR != nil
	var closedSuperseded []int
	if !in.Sequential {
		closedSuperseded, prExists, err = r.closeSupersededPRs(ctx, branch, title, in, prExists)
		if err != nil {
			return Outcome{}, err
		}
	}

	if !rebased {
		if err := r.pushBranchContent(ctx, branch, title, branchExists, in); err != nil {
			if errors.Is(err, errBranchModifiedByHuman) {
				return Outcome{PRURL: prURL, SupersededPRs: closedSuperseded}, nil
			}
			return Outcome{}, fmt.Errorf("committing update to %s: %w", branch, err)
		}
	}

	if !prExists {
		url, err := r.createPullRequest(ctx, branch, title, body, in.DefaultBranch)
		if err != nil {
			return Outcome{}, err
		}
		prURL = url
	}

	return Outcome{PRURL: prURL, SupersededPRs: closedSuperseded}, nil
}

// reopenClosedPRIfAllowed checks for a closed PR on this branch and, per
// RecreateWhen / dashboard actions, either reopens it (returned as the
// second value being non-nil is not how we signal this — see return docs)
// or leaves it closed and blocking.
//
// Returns (reopened, blocked, err): exactly one of reopened/blocked is
// non-nil when err is nil and a closed PR was found; both are nil if no
// closed PR exists at all.
func (r *Reconciler) reopenClosedPRIfAllowed(ctx context.Context, branch string, in Input) (reopened, blocked *PullRequest, err error) {
	log := clog.FromContext(ctx)

	closedPR, err := r.Client.FindClosedPR(ctx, branch)
	if err != nil {
		log.Warn("error checking for closed PR, continuing", "error", err)
	}
	if closedPR == nil {
		return nil, nil, nil
	}

	manualRecreate := in.DashboardActions.RecreateAll || in.DashboardActions.RecreatePR[branch]
	allow := manualRecreate

	if !allow {
		switch in.RecreateWhen {
		case "always":
			allow = true
		case "never":
			allow = false
		default: // "auto"
			if !in.Sequential {
				closedVersion := extractVersionFromPRTitle(closedPR.Title)
				allow = closedVersion != "" && versioning.Compare(ctx, closedVersion, in.Version) < 0
			}
		}
	}

	if !allow {
		log.Info("closed PR exists and recreate not requested, leaving it closed",
			"pr", closedPR.Number, "recreate_when", in.RecreateWhen, "sequential", in.Sequential)
		return nil, closedPR, nil
	}

	log.Info("recreating closed PR", "pr", closedPR.Number)
	if err := r.Client.ReopenPullRequest(ctx, closedPR.Number); err != nil {
		log.Warn("failed to reopen closed PR, will create new one instead", "pr", closedPR.Number, "error", err)
		return nil, nil, nil
	}
	closedPR.State = "open"
	return closedPR, nil, nil
}

func (r *Reconciler) retargetBaseIfDrifted(ctx context.Context, pr *PullRequest, defaultBranch string) {
	log := clog.FromContext(ctx)
	if pr.BaseRef == "" || pr.BaseRef == defaultBranch {
		return
	}
	log.Info("PR base branch has drifted, retargeting", "pr", pr.Number, "old_base", pr.BaseRef, "new_base", defaultBranch)
	if err := r.Client.RetargetPullRequestBase(ctx, pr.Number, defaultBranch); err != nil {
		log.Warn("failed to retarget PR base branch", "error", err)
		return
	}
	pr.BaseRef = defaultBranch
}

func (r *Reconciler) closeIfAlreadyOnDefaultBranch(ctx context.Context, branch string, pr *PullRequest, in Input) (closed bool, err error) {
	log := clog.FromContext(ctx)

	remoteContent, err := r.Client.FileContent(ctx, in.RepoAPIPath, in.DefaultBranch)
	if err != nil {
		log.Debug("could not fetch file from default branch, skipping already-applied check", "error", err)
		return false, nil
	}

	remoteVersion, ok := parsePackageVersion(ctx, remoteContent)
	if !ok {
		return false, nil
	}
	if versioning.Compare(ctx, remoteVersion, in.Version) < 0 {
		return false, nil
	}

	log.Info("default branch already has this version or newer, closing PR as redundant",
		"pr", pr.Number, "default_branch_version", remoteVersion, "pr_version", in.Version)

	if err := r.Client.CreateIssueComment(ctx, pr.Number, fmt.Sprintf(
		"This update (or a newer one) has already been applied directly to `%s`. Closing this PR as it is no longer needed.",
		in.DefaultBranch)); err != nil {
		log.Warn("failed to post already-applied comment", "pr", pr.Number, "error", err)
	}
	if err := r.Client.ClosePullRequest(ctx, pr.Number); err != nil {
		return false, fmt.Errorf("closing already-applied PR: %w", err)
	}
	if err := r.Client.DeleteRef(ctx, "heads/"+branch); err != nil {
		log.Warn("failed to delete branch after closing already-applied PR", "branch", branch, "error", err)
	}
	return true, nil
}

func (r *Reconciler) computeRebaseDecision(ctx context.Context, branch string, pr *PullRequest, in Input) (rebaseNeeded bool) {
	log := clog.FromContext(ctx)
	hasConflict := isBranchConflicted(pr)

	comp, err := r.Client.CompareCommits(ctx, in.DefaultBranch, branch)
	if err != nil {
		log.Warn("could not compare branch against default, skipping staleness/modification checks", "error", err)
	}
	stale := comp != nil && comp.stale()

	requireUpToDate := false
	if in.RebaseWhen == "auto" {
		var ruErr error
		requireUpToDate, ruErr = r.Client.RequiresUpToDateBranch(ctx, in.DefaultBranch)
		if ruErr != nil {
			log.Warn("could not determine branch protection requirements", "error", ruErr)
		}
	}

	manualRebase := in.DashboardActions.RebaseAll || in.DashboardActions.RebasePR[branch] || isRebaseRequested(pr.Body)
	rebaseNeeded = shouldRebase(manualRebase, in.RebaseWhen, hasConflict, stale, requireUpToDate)

	if rebaseNeeded && !manualRebase {
		if comp == nil {
			log.Warn("could not determine if branch was modified, skipping automatic rebase")
			return false
		}
		if isBranchModified(ctx, comp, branch, in.Bot) {
			log.Info("branch has human commits, skipping automatic rebase (request manual rebase to override)", "pr", pr.Number)
			return false
		}
	}
	return rebaseNeeded
}

func shouldRebase(manualRebase bool, rebaseWhen string, hasConflict, stale, requireUpToDate bool) bool {
	if manualRebase {
		return true
	}
	switch rebaseWhen {
	case "never":
		return false
	case "conflicted":
		return hasConflict
	case "behind-base-branch":
		return stale
	case "auto":
		if requireUpToDate {
			return stale
		}
		return hasConflict
	default:
		return false
	}
}

func isBranchModified(ctx context.Context, comp *Comparison, branch, bot string) bool {
	log := clog.FromContext(ctx)
	for _, c := range comp.Commits {
		if c.AuthorLogin != "" && strings.EqualFold(c.AuthorLogin, bot) {
			continue
		}
		log.Warn("commit did not match expected bot identity, treating branch as human-modified",
			"branch", branch, "commit_sha", c.SHA, "author_login", c.AuthorLogin,
			"author_email", c.AuthorEmail, "committer_email", c.CommitterEmail, "expected_bot_login", bot)
		return true
	}
	return false
}

func (r *Reconciler) branchContentUpToDate(ctx context.Context, branch, prevTitle, newTitle, path string, content []byte) (bool, error) {
	remote, err := r.Client.FileContent(ctx, path, branch)
	if err != nil {
		return false, fmt.Errorf("fetching file from PR branch: %w", err)
	}
	return fingerprint(remote, prevTitle) == fingerprint(string(content), newTitle), nil
}

func (r *Reconciler) executeRebase(ctx context.Context, branch, title string, in Input, pr *PullRequest) error {
	log := clog.FromContext(ctx)

	latestMainSHA, err := r.Client.BranchTipSHA(ctx, in.DefaultBranch)
	if err != nil {
		return fmt.Errorf("getting default branch ref for rebase: %w", err)
	}
	if _, err := r.Client.CommitFile(ctx, branch, latestMainSHA, true, in.RepoAPIPath, in.Content, title); err != nil {
		return fmt.Errorf("rebasing branch: %w", err)
	}
	log.Info("successfully rebased branch to a clean commit", "pr", pr.Number)

	uncheckedBody := uncheckRebaseBox(pr.Body)
	if uncheckedBody != pr.Body {
		if err := r.Client.SetPullRequestBody(ctx, pr.Number, uncheckedBody); err != nil {
			log.Warn("failed to uncheck rebase box in PR body", "error", err)
		}
	}
	return nil
}

func (r *Reconciler) closeSupersededPRs(ctx context.Context, branch, title string, in Input, prExists bool) (closed []int, stillExists bool, err error) {
	log := clog.FromContext(ctx)
	stillExists = prExists

	all, err := r.Client.ListOpenPRsWithTitlePrefix(ctx, in.PackageName+"/")
	if err != nil {
		return nil, stillExists, fmt.Errorf("listing all open PRs: %w", err)
	}

	for _, pr := range all {
		remoteContent, err := r.Client.FileContent(ctx, in.RepoAPIPath, branch)
		if err != nil {
			log.Warn("could not fetch config from PR branch, skipping supersede check", "number", pr.Number, "error", err)
			continue
		}
		remoteVersion, ok := parsePackageVersion(ctx, remoteContent)
		if !ok || versioning.Compare(ctx, remoteVersion, in.Version) >= 0 {
			continue
		}

		if err := r.Client.CreateIssueComment(ctx, pr.Number, fmt.Sprintf(
			"This PR has been superseded by a newer version update: **%s**. Closing automatically.", title)); err != nil {
			log.Warn("failed to post superseded comment", "number", pr.Number, "error", err)
		}
		if err := r.Client.ClosePullRequest(ctx, pr.Number); err != nil {
			log.Warn("failed to close outdated PR", "number", pr.Number, "error", err)
			continue
		}
		closed = append(closed, pr.Number)
		stillExists = false
	}
	return closed, stillExists, nil
}

func (r *Reconciler) pushBranchContent(ctx context.Context, branch, message string, branchExists bool, in Input) error {
	targetBranch := in.DefaultBranch
	if branchExists {
		comp, err := r.Client.CompareCommits(ctx, in.DefaultBranch, branch)
		if err != nil {
			return fmt.Errorf("checking branch modification status: %w", err)
		}
		if isBranchModified(ctx, comp, branch, in.Bot) {
			return errBranchModifiedByHuman
		}
		targetBranch = branch
	}

	parentSHA, err := r.Client.BranchTipSHA(ctx, targetBranch)
	if err != nil {
		return fmt.Errorf("resolving current tip of %s: %w", targetBranch, err)
	}

	return withRetry(ctx, 3, func() error {
		_, e := r.Client.CommitFile(ctx, branch, parentSHA, branchExists, in.RepoAPIPath, in.Content, message)
		return e
	})
}

func (r *Reconciler) createPullRequest(ctx context.Context, head, title, body, base string) (string, error) {
	log := clog.FromContext(ctx)

	newPR, err := r.Client.CreatePullRequest(ctx, head, base, title, body)
	if err != nil {
		if isPRAlreadyExistsErr(err) {
			log.Warn("PR was created concurrently by another run, treating as success")
			return "", nil
		}
		if is5xxErr(err) {
			log.Warn("server error creating PR, deleting branch so next run starts clean", "branch", head, "error", err)
			if dErr := r.Client.DeleteRef(ctx, "heads/"+head); dErr != nil {
				log.Warn("failed to delete branch after failed PR creation", "error", dErr)
			}
		}
		return "", fmt.Errorf("creating PR: %w", err)
	}

	if err := r.Client.AddLabels(ctx, newPR.Number, []string{automationLabel, "request-version-update"}); err != nil {
		log.Warn("failed to add labels", "error", err)
	}
	log.Info("PR is ready!", "url", newPR.HTMLURL)
	return newPR.HTMLURL, nil
}

// parsePackageVersion parses a melange config's package.version field out
// of raw file content fetched from GitHub. Failures are non-fatal to the
// caller by design — a config we can't parse just can't participate in
// the already-applied / superseded checks.
func parsePackageVersion(ctx context.Context, content string) (version string, ok bool) {
	tmp, err := os.CreateTemp("", "melange-*.yaml")
	if err != nil {
		return "", false
	}
	defer func() {
		_ = os.Remove(tmp.Name())
	}()

	_, _ = tmp.WriteString(content)
	_ = tmp.Close()

	cfg, err := config.ParseConfiguration(ctx, tmp.Name())
	if err != nil {
		return "", false
	}
	return cfg.Package.Version, true
}
