package renovator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
)

var errBranchModifiedByHuman = errors.New("branch has commits from someone other than this tool and will not be automatically rebuilt; resolve conflicts manually")

type repoManager struct {
	gh      *github.Client
	owner   string
	repo    string
	mutator mutator
}

func newRepoManager(gh *github.Client, owner, repo string, m mutator) *repoManager {
	return &repoManager{gh: gh, owner: owner, repo: repo, mutator: m}
}

func detectBotLogin(ctx context.Context, gh *github.Client) (string, error) {
	reqBody := struct {
		Query string `json:"query"`
	}{
		Query: `query { viewer { login } }`,
	}

	req, err := gh.NewRequest("POST", "graphql", reqBody)
	if err != nil {
		return "", fmt.Errorf("building viewer identity query: %w", err)
	}

	var result struct {
		Data struct {
			Viewer struct {
				Login string `json:"login"`
			} `json:"viewer"`
		} `json:"data"`
	}

	if _, err := gh.Do(ctx, req, &result); err != nil {
		return "", fmt.Errorf("querying authenticated identity: %w", err)
	}

	login := result.Data.Viewer.Login
	if login == "" {
		return "", errors.New("viewer query returned an empty login")
	}
	return login, nil
}

// buildPRMetadata derives the branch name, title, and body for a
// package's update PR from its name and resolved version.
func buildPRMetadata(pkgName string, result versionResult) (branch, title, body string) {
	branch = fmt.Sprintf("update-%s", pkgName)
	title = fmt.Sprintf("%s/%s package update", pkgName, result.Version)
	body = "<p align=\"center\">\n" +
		"  <img src=\"https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg\" />\n" +
		"</p>" + prRebaseControl
	return branch, title, body
}

type prOutcome struct {
	URL               string
	ClosedSuperseded  []int
	BlockedByClosedPR bool
	ClosedPRUrl       string
}

func (rm *repoManager) ensurePR(ctx context.Context, file packageFile, pkgName string, result versionResult, sequential bool, cfg runtimeConfig, defaultBranch string) (prOutcome, error) {
	log := clog.FromContext(ctx)

	content, err := readPackageFile(file.Path)
	if err != nil {
		return prOutcome{}, err
	}

	prBranch, prTitle, prBody := buildPRMetadata(pkgName, result)

	branchExists, openPR, err := rm.locateOpenPR(ctx, prBranch)
	if err != nil {
		return prOutcome{}, err
	}

	if openPR == nil {
		closedPR, cErr := rm.findClosedPR(ctx, prBranch)
		if cErr != nil {
			log.Warn("error checking for closed PR, continuing", "error", cErr)
		}
		if closedPR != nil {
			manualRecreate := cfg.DashboardActions.RecreateAll || cfg.DashboardActions.RecreatePR[prBranch]
			allow := manualRecreate

			if !allow {
				switch cfg.RecreateWhen {
				case "always":
					allow = true
				case "never":
					allow = false
				default:
					if !sequential {
						closedVersion := extractVersionFromPRTitle(closedPR.GetTitle())
						allow = closedVersion != "" && compareVersions(ctx, closedVersion, result.Version) < 0
					}
				}
			}

			if !allow {
				log.Info("closed PR exists and recreate not requested, leaving it closed",
					"pr", closedPR.GetNumber(), "recreate_when", cfg.RecreateWhen, "sequential", sequential)
				return prOutcome{BlockedByClosedPR: true, ClosedPRUrl: closedPR.GetHTMLURL()}, nil
			}

			log.Info("recreating closed PR", "pr", closedPR.GetNumber())
			if err := rm.mutator.EditPullRequest(ctx, rm.owner, rm.repo, closedPR.GetNumber(), &github.PullRequest{
				State: github.Ptr("open"),
			}); err != nil {
				log.Warn("failed to reopen closed PR, will create new one instead", "pr", closedPR.GetNumber(), "error", err)
			} else {
				closedPR.State = github.Ptr("open")
				openPR = closedPR
			}
		}
	}

	prURL := ""
	rebased := false

	if openPR != nil {
		openPR, err = rm.retargetPRBase(ctx, openPR, defaultBranch)
		if err != nil {
			return prOutcome{}, err
		}
		prURL = openPR.GetHTMLURL()

		closed, cErr := rm.closeIfAlreadyOnDefaultBranch(ctx, defaultBranch, file.RepoAPIPath, prBranch, openPR, result)
		if cErr != nil {
			return prOutcome{}, cErr
		}
		if closed {
			return prOutcome{ClosedSuperseded: []int{openPR.GetNumber()}}, nil
		}

		rebaseNeeded, _ := rm.computeRebaseDecision(ctx, defaultBranch, prBranch, openPR, cfg)

		upToDate, err := rm.branchContentUpToDate(ctx, file.RepoAPIPath, prBranch, openPR.GetTitle(), content, prTitle)
		if err != nil {
			return prOutcome{}, err
		}

		if upToDate && !rebaseNeeded {
			log.Debug("content and title unchanged and branch up to date, nothing to do")
			return prOutcome{URL: prURL}, nil
		}

		if rebaseNeeded {
			if err := rm.executeRebase(ctx, defaultBranch, prBranch, file.RepoAPIPath, content, prTitle, openPR); err != nil {
				return prOutcome{}, err
			}
			rebased = true
		}
	}

	prExists := openPR != nil
	var closedSuperseded []int
	if !sequential {
		closedSuperseded, prExists, err = rm.closeSupersededPRs(ctx, pkgName, file.RepoAPIPath, prBranch, prTitle, result, prExists)
		if err != nil {
			return prOutcome{}, err
		}
	}

	if !rebased {
		if _, err := rm.pushBranchContent(ctx, defaultBranch, prBranch, branchExists, file.RepoAPIPath, content, prTitle, cfg.Bot); err != nil {
			if errors.Is(err, errBranchModifiedByHuman) {
				return prOutcome{URL: prURL, ClosedSuperseded: closedSuperseded}, nil
			}
			return prOutcome{}, fmt.Errorf("committing update to %s: %w", prBranch, err)
		}
	}

	if !prExists {
		url, err := rm.createPullRequest(ctx, prBranch, defaultBranch, prTitle, prBody)
		if err != nil {
			return prOutcome{}, err
		}
		prURL = url
	}

	return prOutcome{URL: prURL, ClosedSuperseded: closedSuperseded}, nil
}

func readPackageFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return content, nil
}

func (rm *repoManager) locateOpenPR(ctx context.Context, prBranch string) (branchExists bool, openPR *github.PullRequest, err error) {
	err = withRetry(ctx, 3, func() error {
		_, resp, e := rm.gh.Repositories.GetBranch(ctx, rm.owner, rm.repo, prBranch, 0)
		branchExists = e == nil
		if !branchExists && (resp == nil || resp.StatusCode != 404) {
			return e
		}
		return nil
	})
	if err != nil {
		return false, nil, fmt.Errorf("checking branch existence: %w", err)
	}

	err = withRetry(ctx, 3, func() error {
		var e error
		var branchPRs []*github.PullRequest
		branchPRs, _, e = rm.gh.PullRequests.List(ctx, rm.owner, rm.repo, &github.PullRequestListOptions{
			State: "open",
			Head:  fmt.Sprintf("%s:%s", rm.owner, prBranch),
		})
		if len(branchPRs) > 0 {
			openPR = branchPRs[0]
		}
		return e
	})
	if err != nil {
		return false, nil, fmt.Errorf("checking for existing branch PRs: %w", err)
	}

	return branchExists, openPR, nil
}

func (rm *repoManager) getDefaultBranch(ctx context.Context) string {
	repoInfo, _, err := rm.gh.Repositories.Get(ctx, rm.owner, rm.repo)
	if err != nil {
		return "main"
	}
	return repoInfo.GetDefaultBranch()
}

func (rm *repoManager) retargetPRBase(ctx context.Context, openPR *github.PullRequest, defaultBranch string) (*github.PullRequest, error) {
	log := clog.FromContext(ctx)

	fullPR, _, err := rm.gh.PullRequests.Get(ctx, rm.owner, rm.repo, openPR.GetNumber())
	if err == nil {
		openPR = fullPR
	}

	if openPR.GetBase().GetRef() != "" && openPR.GetBase().GetRef() != defaultBranch {
		log.Info("PR base branch has drifted, retargeting",
			"pr", openPR.GetNumber(), "old_base", openPR.GetBase().GetRef(), "new_base", defaultBranch)
		if uErr := rm.mutator.EditPullRequest(ctx, rm.owner, rm.repo, openPR.GetNumber(), &github.PullRequest{
			Base: &github.PullRequestBranch{Ref: github.Ptr(defaultBranch)},
		}); uErr != nil {
			log.Warn("failed to retarget PR base branch", "error", uErr)
		}
	}

	return openPR, nil
}

func (rm *repoManager) closeIfAlreadyOnDefaultBranch(ctx context.Context, defaultBranch, fileAPIPath, prBranch string, openPR *github.PullRequest, result versionResult) (closed bool, err error) {
	log := clog.FromContext(ctx)

	remoteFile, _, _, gErr := rm.gh.Repositories.GetContents(ctx, rm.owner, rm.repo, fileAPIPath,
		&github.RepositoryContentGetOptions{Ref: defaultBranch})
	if gErr != nil {
		log.Debug("could not fetch file from default branch, skipping already-applied check", "error", gErr)
		return false, nil
	}
	remoteContent, cErr := remoteFile.GetContent()
	if cErr != nil {
		return false, nil
	}

	tmp, tErr := os.CreateTemp("", "melange-*.yaml")
	if tErr != nil {
		return false, nil
	}
	tmpName := tmp.Name()
	_, _ = tmp.WriteString(remoteContent)
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	remoteCfg, pErr := config.ParseConfiguration(ctx, tmpName)
	if pErr != nil {
		return false, nil
	}

	if compareVersions(ctx, remoteCfg.Package.Version, result.Version) < 0 {
		return false, nil
	}

	log.Info("default branch already has this version or newer, closing PR as redundant",
		"pr", openPR.GetNumber(), "default_branch_version", remoteCfg.Package.Version, "pr_version", result.Version)

	if cErr := rm.mutator.CreateIssueComment(ctx, rm.owner, rm.repo, openPR.GetNumber(), fmt.Sprintf(
		"This update (or a newer one) has already been applied directly to `%s`. Closing this PR as it is no longer needed.",
		defaultBranch)); cErr != nil {
		log.Warn("failed to post already-applied comment", "pr", openPR.GetNumber(), "error", cErr)
	}

	if eErr := rm.mutator.EditPullRequest(ctx, rm.owner, rm.repo, openPR.GetNumber(), &github.PullRequest{
		State: github.Ptr("closed"),
	}); eErr != nil {
		return false, fmt.Errorf("closing already-applied PR: %w", eErr)
	}

	if dErr := rm.mutator.DeleteRef(ctx, rm.owner, rm.repo, "heads/"+prBranch); dErr != nil {
		log.Warn("failed to delete branch after closing already-applied PR", "branch", prBranch, "error", dErr)
	}

	return true, nil
}

func (rm *repoManager) computeRebaseDecision(ctx context.Context, defaultBranch, prBranch string, openPR *github.PullRequest, cfg runtimeConfig) (rebaseNeeded, manualRebase bool) {
	log := clog.FromContext(ctx)

	hasConflict := isBranchConflicted(openPR)

	comp, cErr := rm.compareAgainstDefault(ctx, defaultBranch, prBranch)
	if cErr != nil {
		log.Warn("could not compare PR branch against default, skipping staleness/modification checks", "error", cErr)
	}

	stale := comp != nil && isBranchStale(comp)

	requireUpToDate := false
	if cfg.RebaseWhen == "auto" {
		var ruErr error
		requireUpToDate, ruErr = rm.requiresUpToDateBranch(ctx, defaultBranch)
		if ruErr != nil {
			log.Warn("could not determine branch protection requirements", "error", ruErr)
		}
	}

	manualRebase = cfg.DashboardActions.RebaseAll ||
		cfg.DashboardActions.RebasePR[prBranch] ||
		isRebaseRequested(openPR.GetBody())

	rebaseNeeded = shouldRebase(manualRebase, cfg.RebaseWhen, hasConflict, stale, requireUpToDate)

	if rebaseNeeded && !manualRebase {
		if comp == nil {
			log.Warn("could not determine if branch was modified, skipping automatic rebase")
			rebaseNeeded = false
		} else if rm.isBranchModified(ctx, comp, prBranch, cfg.Bot) {
			log.Info("branch has human commits, skipping automatic rebase (request manual rebase to override)",
				"pr", openPR.GetNumber())
			rebaseNeeded = false
		}
	}

	return rebaseNeeded, manualRebase
}

func (rm *repoManager) branchContentUpToDate(ctx context.Context, fileAPIPath, prBranch, prevTitle string, content []byte, newTitle string) (bool, error) {
	var remoteFile *github.RepositoryContent
	err := withRetry(ctx, 3, func() error {
		var e error
		remoteFile, _, _, e = rm.gh.Repositories.GetContents(ctx, rm.owner, rm.repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		return e
	})
	if err != nil {
		return false, fmt.Errorf("fetching file from PR branch: %w", err)
	}

	remoteContent, _ := remoteFile.GetContent()

	oldFP := fingerprint(remoteContent, prevTitle)
	newFP := fingerprint(string(content), newTitle)

	return oldFP == newFP, nil
}

func (rm *repoManager) executeRebase(ctx context.Context, defaultBranch, prBranch, fileAPIPath string, content []byte, prTitle string, openPR *github.PullRequest) error {
	log := clog.FromContext(ctx)

	mainRef, _, gErr := rm.gh.Git.GetRef(ctx, rm.owner, rm.repo, "heads/"+defaultBranch)
	if gErr != nil {
		return fmt.Errorf("getting default branch ref for rebase: %w", gErr)
	}
	latestMainSHA := mainRef.GetObject().GetSHA()

	if _, err := rm.mutator.CommitFile(ctx, rm.owner, rm.repo, prBranch, latestMainSHA, true, fileAPIPath, content, prTitle); err != nil {
		return fmt.Errorf("rebasing branch: %w", err)
	}
	log.Info("successfully rebased branch to a clean commit", "pr", openPR.GetNumber())

	uncheckedBody := uncheckRebaseBox(openPR.GetBody())
	if uncheckedBody != openPR.GetBody() {
		if uErr := rm.mutator.EditPullRequest(ctx, rm.owner, rm.repo, openPR.GetNumber(), &github.PullRequest{
			Body: github.Ptr(uncheckedBody),
		}); uErr != nil {
			log.Warn("failed to uncheck rebase box in PR body", "error", uErr)
		}
	}

	return nil
}

func (rm *repoManager) closeSupersededPRs(ctx context.Context, pkgName, fileAPIPath, prBranch, prTitle string, result versionResult, prExists bool) (closedSuperseded []int, stillExists bool, err error) {
	log := clog.FromContext(ctx)
	stillExists = prExists

	var allPRs []*github.PullRequest
	err = withRetry(ctx, 3, func() error {
		var e error
		allPRs, _, e = rm.gh.PullRequests.List(ctx, rm.owner, rm.repo, &github.PullRequestListOptions{State: "open"})
		return e
	})
	if err != nil {
		return nil, stillExists, fmt.Errorf("listing all open PRs: %w", err)
	}

	for _, pr := range allPRs {
		if !strings.HasPrefix(pr.GetTitle(), pkgName+"/") {
			continue
		}
		hasAutomationLabel := false
		for _, label := range pr.Labels {
			if label.GetName() == "automated pr" {
				hasAutomationLabel = true
				break
			}
		}
		if !hasAutomationLabel {
			continue
		}

		remoteFile, _, _, gErr := rm.gh.Repositories.GetContents(ctx, rm.owner, rm.repo, fileAPIPath,
			&github.RepositoryContentGetOptions{Ref: prBranch})
		if gErr != nil {
			log.Warn("could not fetch config from PR branch, skipping supersede check",
				"number", pr.GetNumber(), "error", gErr)
			continue
		}
		remoteContent, cErr := remoteFile.GetContent()
		if cErr != nil {
			continue
		}

		tmp, tErr := os.CreateTemp("", "melange-*.yaml")
		if tErr != nil {
			continue
		}
		tmpName := tmp.Name()
		_, _ = tmp.WriteString(remoteContent)
		_ = tmp.Close()
		remoteCfg, pErr := config.ParseConfiguration(ctx, tmpName)
		_ = os.Remove(tmpName)
		if pErr != nil {
			continue
		}

		if compareVersions(ctx, remoteCfg.Package.Version, result.Version) >= 0 {
			continue
		}

		if cErr := rm.mutator.CreateIssueComment(ctx, rm.owner, rm.repo, pr.GetNumber(), fmt.Sprintf(
			"This PR has been superseded by a newer version update: **%s**. Closing automatically.",
			prTitle)); cErr != nil {
			log.Warn("failed to post superseded comment", "number", pr.GetNumber(), "error", cErr)
		}
		if eErr := rm.mutator.EditPullRequest(ctx, rm.owner, rm.repo, pr.GetNumber(), &github.PullRequest{
			State: github.Ptr("closed"),
		}); eErr != nil {
			log.Warn("failed to close outdated PR", "number", pr.GetNumber(), "error", eErr)
		} else {
			closedSuperseded = append(closedSuperseded, pr.GetNumber())
		}
		stillExists = false
	}

	return closedSuperseded, stillExists, nil
}

func (rm *repoManager) pushBranchContent(ctx context.Context, defaultBranch, prBranch string, branchExists bool, relPath string, content []byte, commitMessage string, bot string) (newCommitSHA string, err error) {
	log := clog.FromContext(ctx)

	targetBranch := defaultBranch
	if branchExists {
		comp, cErr := rm.compareAgainstDefault(ctx, defaultBranch, prBranch)
		if cErr != nil {
			return "", fmt.Errorf("checking branch modification status: %w", cErr)
		}
		if rm.isBranchModified(ctx, comp, prBranch, bot) {
			return "", errBranchModifiedByHuman
		}
		targetBranch = prBranch
	}

	var parentSHA string
	err = withRetry(ctx, 3, func() error {
		ref, _, e := rm.gh.Git.GetRef(ctx, rm.owner, rm.repo, "refs/heads/"+targetBranch)
		if e != nil {
			return e
		}
		parentSHA = ref.Object.GetSHA()
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("resolving current tip of %s: %w", targetBranch, err)
	}

	err = withRetry(ctx, 3, func() error {
		var e error
		newCommitSHA, e = rm.mutator.CommitFile(ctx, rm.owner, rm.repo, prBranch, parentSHA, branchExists, relPath, content, commitMessage)
		return e
	})
	if err != nil {
		log.Debug("commit failed", "branch", prBranch, "error", err)
		return "", err
	}
	return newCommitSHA, nil
}

func (rm *repoManager) createPullRequest(ctx context.Context, prBranch, defaultBranch, prTitle, prBody string) (string, error) {
	log := clog.FromContext(ctx)

	newPR, err := rm.mutator.CreatePullRequest(ctx, rm.owner, rm.repo, prBranch, defaultBranch, prTitle, prBody)
	if err != nil {
		if isPRAlreadyExistsErr(err) {
			log.Warn("PR was created concurrently by another run, treating as success")
			return "", nil
		}
		if is5xxErr(err) {
			log.Warn("server error creating PR, deleting branch so next run starts clean",
				"branch", prBranch, "error", err)
			if dErr := rm.mutator.DeleteRef(ctx, rm.owner, rm.repo, "heads/"+prBranch); dErr != nil {
				log.Warn("failed to delete branch after failed PR creation", "error", dErr)
			}
		}
		return "", fmt.Errorf("creating PR: %w", err)
	}

	if lErr := rm.mutator.AddLabels(ctx, rm.owner, rm.repo, newPR.GetNumber(),
		[]string{"automated pr", "request-version-update"}); lErr != nil {
		log.Warn("failed to add labels", "error", lErr)
	}

	log.Info("PR is ready!", "url", newPR.GetHTMLURL())
	return newPR.GetHTMLURL(), nil
}

func isPRAlreadyExistsErr(err error) bool {
	if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok {
		if ghErr.Message == "Validation Failed" {
			for _, e := range ghErr.Errors {
				if strings.HasPrefix(e.Message, "A pull request already exists") {
					return true
				}
			}
		}
	}
	return false
}

func isRefAlreadyExistsErr(err error) bool {
	if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok {
		for _, e := range ghErr.Errors {
			if e.Code == "already_exists" {
				return true
			}
		}
	}
	return false
}

func is5xxErr(err error) bool {
	if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok && ghErr.Response != nil {
		return ghErr.Response.StatusCode >= 500
	}
	return false
}

func isRateLimitErr(err error) (retryAfter time.Duration, ok bool) {
	if rle, ok := errors.AsType[*github.RateLimitError](err); ok {
		return time.Until(rle.Rate.Reset.Time), true
	}
	if arle, ok := errors.AsType[*github.AbuseRateLimitError](err); ok {
		if arle.RetryAfter != nil {
			return *arle.RetryAfter, true
		}
		return 60 * time.Second, true
	}
	return 0, false
}

func withRetry(ctx context.Context, maxAttempts int, fn func() error) error {
	log := clog.FromContext(ctx)
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		wait, isRateLimit := isRateLimitErr(lastErr)
		if !isRateLimit || attempt == maxAttempts {
			return lastErr
		}
		if wait <= 0 || wait > 15*time.Minute {
			wait = 30 * time.Second
		}
		log.Warn("rate limited, backing off",
			"attempt", attempt, "wait", wait, "error", lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastErr
}

func isBranchConflicted(pr *github.PullRequest) bool {
	if pr == nil {
		return false
	}
	if pr.Mergeable != nil && !*pr.Mergeable {
		return true
	}
	return pr.GetMergeableState() == "dirty"
}

func (rm *repoManager) compareAgainstDefault(ctx context.Context, defaultBranch, prBranch string) (*github.CommitsComparison, error) {
	comp, _, err := rm.gh.Repositories.CompareCommits(ctx, rm.owner, rm.repo, defaultBranch, prBranch, nil)
	if err != nil {
		return nil, fmt.Errorf("comparing %s against %s: %w", prBranch, defaultBranch, err)
	}
	return comp, nil
}

func isBranchStale(comp *github.CommitsComparison) bool {
	return comp.GetBehindBy() > 0
}

func (rm *repoManager) isBranchModified(ctx context.Context, comp *github.CommitsComparison, prBranch, bot string) bool {
	log := clog.FromContext(ctx)

	if len(comp.Commits) == 0 {
		return false
	}

	for _, c := range comp.Commits {
		authorLogin := c.GetAuthor().GetLogin()

		if authorLogin != "" && strings.EqualFold(authorLogin, bot) {
			continue
		}

		log.Warn("commit did not match expected bot identity, treating branch as human-modified",
			"branch", prBranch,
			"commit_sha", c.GetSHA(),
			"author_login", authorLogin,
			"author_email", c.GetCommit().GetAuthor().GetEmail(),
			"committer_email", c.GetCommit().GetCommitter().GetEmail(),
			"expected_bot_login", bot)

		return true
	}

	return false
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (rm *repoManager) requiresUpToDateBranch(ctx context.Context, branch string) (bool, error) {
	protection, _, err := rm.gh.Repositories.GetBranchProtection(ctx, rm.owner, rm.repo, branch)
	if err != nil {
		if _, ok := err.(*github.ErrorResponse); ok {
			return false, nil
		}
		return false, err
	}

	return protection.RequiredStatusChecks != nil &&
			protection.RequiredStatusChecks.Strict,
		nil
}

func shouldRebase(manualRebase bool, rebaseWhen string, hasConflict bool, stale bool, requireUpToDate bool) bool {
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

func (rm *repoManager) findClosedPR(ctx context.Context, prBranch string) (*github.PullRequest, error) {
	prs, _, err := rm.gh.PullRequests.List(ctx, rm.owner, rm.repo, &github.PullRequestListOptions{
		State: "closed",
		Head:  fmt.Sprintf("%s:%s", rm.owner, prBranch),
		ListOptions: github.ListOptions{
			PerPage: 5,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing closed PRs for branch: %w", err)
	}
	if len(prs) == 0 {
		return nil, nil
	}

	candidate := prs[0]
	hasAutomationLabel := false
	for _, l := range candidate.Labels {
		if l.GetName() == "automated pr" {
			hasAutomationLabel = true
			break
		}
	}
	if !hasAutomationLabel || candidate.MergedAt != nil {
		return nil, nil
	}

	return candidate, nil
}

func extractVersionFromPRTitle(title string) string {
	nameVersion, _, ok := strings.Cut(title, " ")
	if !ok {
		return ""
	}
	_, version, ok := strings.Cut(nameVersion, "/")
	if !ok {
		return ""
	}
	return version
}
