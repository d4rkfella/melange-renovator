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
	dashboardChecks dashboardChecks,
	rebaseWhen string,
	bot string,
) (string, []int, error) {
	log := clog.FromContext(ctx)

	content, fileAPIPath, err := readPackageFile(filePath)
	if err != nil {
		return "", nil, err
	}

	branchExists, openPR, err := locateOpenPR(ctx, gh, owner, repo, prBranch, dryRun)
	if err != nil {
		return "", nil, err
	}

	defaultBranch := getDefaultBranch(ctx, gh, owner, repo)

	prURL := ""
	rebased := false

	if openPR != nil {
		openPR, err = retargetPRBase(ctx, gh, owner, repo, openPR, defaultBranch, dryRun)
		if err != nil {
			return "", nil, err
		}
		prURL = openPR.GetHTMLURL()

		closed, cErr := closeIfAlreadyOnDefaultBranch(ctx, gh, owner, repo, defaultBranch, fileAPIPath, prBranch, openPR, result, dryRun)
		if cErr != nil {
			return "", nil, cErr
		}
		if closed {
			return "", []int{openPR.GetNumber()}, nil
		}

		rebaseNeeded, _ := computeRebaseDecision(ctx, gh, owner, repo, defaultBranch, prBranch, openPR, rebaseWhen, dashboardChecks, bot)

		upToDate, err := branchContentUpToDate(ctx, gh, owner, repo, fileAPIPath, prBranch, openPR.GetTitle(), content, prTitle)
		if err != nil {
			return "", nil, err
		}

		if upToDate && !rebaseNeeded {
			log.Debug("content and title unchanged and branch up to date, nothing to do")
			return prURL, nil, nil
		}

		if rebaseNeeded && !dryRun {
			if err := executeRebase(ctx, gh, owner, repo, defaultBranch, prBranch, fileAPIPath, content, prTitle, openPR); err != nil {
				return "", nil, err
			}
			rebased = true
		}
	}

	prExists := openPR != nil
	var closedSuperseded []int
	if !sequential {
		closedSuperseded, prExists, err = closeSupersededPRs(ctx, gh, owner, repo, pkgName, fileAPIPath, prBranch, prTitle, result, prExists, dryRun)
		if err != nil {
			return "", nil, err
		}
	}

	if dryRun {
		return "", closedSuperseded, nil
	}

	if !rebased {
		if _, err := pushBranchContent(ctx, gh, owner, repo, defaultBranch, prBranch, branchExists, fileAPIPath, content, prTitle, bot); err != nil {
			if errors.Is(err, errBranchModifiedByHuman) {
				return prURL, closedSuperseded, nil
			}
			return "", nil, fmt.Errorf("committing update to %s: %w", prBranch, err)
		}
	}

	if !prExists {
		url, err := createPullRequest(ctx, gh, owner, repo, prBranch, defaultBranch, prTitle, prBody)
		if err != nil {
			return "", nil, err
		}
		prURL = url
	}

	return prURL, closedSuperseded, nil
}

func readPackageFile(filePath string) (content []byte, fileAPIPath string, err error) {
	content, err = os.ReadFile(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("reading file: %w", err)
	}
	fileAPIPath = strings.TrimPrefix(filePath, "/github/workspace/")
	return content, fileAPIPath, nil
}

func locateOpenPR(
	ctx context.Context,
	gh *github.Client,
	owner, repo, prBranch string,
	dryRun bool,
) (branchExists bool, openPR *github.PullRequest, err error) {
	log := clog.FromContext(ctx)

	err = withRetry(ctx, 3, func() error {
		_, resp, e := gh.Repositories.GetBranch(ctx, owner, repo, prBranch, 0)
		branchExists = e == nil
		if !branchExists && (resp == nil || resp.StatusCode != 404) {
			return e
		}
		return nil
	})
	if err != nil {
		return false, nil, fmt.Errorf("checking branch existence: %w", err)
	}

	var branchPRs []*github.PullRequest
	err = withRetry(ctx, 3, func() error {
		var e error
		branchPRs, _, e = gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
			State: "open",
			Head:  fmt.Sprintf("%s:%s", owner, prBranch),
		})
		return e
	})
	if err != nil {
		return false, nil, fmt.Errorf("checking for existing branch PRs: %w", err)
	}

	if len(branchPRs) > 0 {
		openPR = branchPRs[0]
	}

	if branchExists && openPR == nil && !dryRun {
		reused, rErr := tryReuseClosedPR(ctx, gh, owner, repo, prBranch)
		if rErr != nil {
			log.Warn("error checking for reusable closed PR, continuing", "error", rErr)
		}
		openPR = reused
	}

	return branchExists, openPR, nil
}

func getDefaultBranch(ctx context.Context, gh *github.Client, owner, repo string) string {
	repoInfo, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "main"
	}
	return repoInfo.GetDefaultBranch()
}

func retargetPRBase(
	ctx context.Context,
	gh *github.Client,
	owner, repo string,
	openPR *github.PullRequest,
	defaultBranch string,
	dryRun bool,
) (*github.PullRequest, error) {
	log := clog.FromContext(ctx)

	fullPR, _, err := gh.PullRequests.Get(ctx, owner, repo, openPR.GetNumber())
	if err == nil {
		openPR = fullPR
	}

	if openPR.GetBase().GetRef() != "" && openPR.GetBase().GetRef() != defaultBranch && !dryRun {
		log.Info("PR base branch has drifted, retargeting",
			"pr", openPR.GetNumber(), "old_base", openPR.GetBase().GetRef(), "new_base", defaultBranch)
		if _, _, uErr := gh.PullRequests.Edit(ctx, owner, repo, openPR.GetNumber(), &github.PullRequest{
			Base: &github.PullRequestBranch{Ref: github.Ptr(defaultBranch)},
		}); uErr != nil {
			log.Warn("failed to retarget PR base branch", "error", uErr)
		}
	}

	return openPR, nil
}

func closeIfAlreadyOnDefaultBranch(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, fileAPIPath, prBranch string,
	openPR *github.PullRequest,
	result versionResult,
	dryRun bool,
) (closed bool, err error) {
	log := clog.FromContext(ctx)

	remoteFile, _, _, gErr := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
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

	if dryRun {
		log.Info("DRY RUN: would close PR as already applied on default branch", "pr", openPR.GetNumber())
		return true, nil
	}

	if _, _, cErr := gh.Issues.CreateComment(ctx, owner, repo, openPR.GetNumber(), &github.IssueComment{
		Body: github.Ptr(fmt.Sprintf(
			"This update (or a newer one) has already been applied directly to `%s`. Closing this PR as it is no longer needed.",
			defaultBranch)),
	}); cErr != nil {
		log.Warn("failed to post already-applied comment", "pr", openPR.GetNumber(), "error", cErr)
	}

	if _, _, eErr := gh.PullRequests.Edit(ctx, owner, repo, openPR.GetNumber(), &github.PullRequest{
		State: github.Ptr("closed"),
	}); eErr != nil {
		return false, fmt.Errorf("closing already-applied PR: %w", eErr)
	}

	if _, dErr := gh.Git.DeleteRef(ctx, owner, repo, "heads/"+prBranch); dErr != nil {
		log.Warn("failed to delete branch after closing already-applied PR", "branch", prBranch, "error", dErr)
	}

	return true, nil
}

func computeRebaseDecision(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, prBranch string,
	openPR *github.PullRequest,
	rebaseWhen string,
	dashboardChecks dashboardChecks,
	bot string,
) (rebaseNeeded, manualRebase bool) {
	log := clog.FromContext(ctx)

	hasConflict := isBranchConflicted(openPR)

	stale, sErr := isBranchStale(ctx, gh, owner, repo, defaultBranch, prBranch)
	if sErr != nil {
		log.Warn("could not determine staleness", "error", sErr)
	}

	requireUpToDate := false
	if rebaseWhen == "auto" {
		var ruErr error
		requireUpToDate, ruErr = requiresUpToDateBranch(ctx, gh, owner, repo, defaultBranch)
		if ruErr != nil {
			log.Warn("could not determine branch protection requirements", "error", ruErr)
		}
	}

	manualRebase = dashboardChecks.RebaseAll ||
		dashboardChecks.RebasePR[prBranch] ||
		isRebaseRequested(openPR.GetBody())

	rebaseNeeded = shouldRebase(manualRebase, rebaseWhen, hasConflict, stale, requireUpToDate)

	if rebaseNeeded && !manualRebase {
		modified, mErr := isBranchModified(ctx, gh, owner, repo, defaultBranch, prBranch, bot)
		if mErr != nil {
			log.Warn("could not determine if branch was modified, skipping automatic rebase", "error", mErr)
			rebaseNeeded = false
		} else if modified {
			log.Info("branch has human commits, skipping automatic rebase (request manual rebase to override)",
				"pr", openPR.GetNumber())
			rebaseNeeded = false
		}
	}

	return rebaseNeeded, manualRebase
}

func branchContentUpToDate(
	ctx context.Context,
	gh *github.Client,
	owner, repo, fileAPIPath, prBranch, prevTitle string,
	content []byte,
	newTitle string,
) (bool, error) {
	var remoteFile *github.RepositoryContent
	err := withRetry(ctx, 3, func() error {
		var e error
		remoteFile, _, _, e = gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
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

func executeRebase(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, prBranch, fileAPIPath string,
	content []byte,
	prTitle string,
	openPR *github.PullRequest,
) error {
	log := clog.FromContext(ctx)

	mainRef, _, gErr := gh.Git.GetRef(ctx, owner, repo, "heads/"+defaultBranch)
	if gErr != nil {
		return fmt.Errorf("getting default branch ref for rebase: %w", gErr)
	}
	latestMainSHA := mainRef.GetObject().GetSHA()

	mainCommit, _, gErr := gh.Git.GetCommit(ctx, owner, repo, latestMainSHA)
	if gErr != nil {
		return fmt.Errorf("getting main commit tree: %w", gErr)
	}

	blob, _, gErr := gh.Git.CreateBlob(ctx, owner, repo, github.Blob{
		Content:  github.Ptr(string(content)),
		Encoding: github.Ptr("utf-8"),
	})
	if gErr != nil {
		return fmt.Errorf("creating blob for rebase: %w", gErr)
	}

	newTree, _, gErr := gh.Git.CreateTree(ctx, owner, repo, mainCommit.Tree.GetSHA(), []*github.TreeEntry{
		{
			Path: new(fileAPIPath),
			Mode: new("100644"),
			Type: new("blob"),
			SHA:  blob.SHA,
		},
	})
	if gErr != nil {
		return fmt.Errorf("creating tree for rebase: %w", gErr)
	}

	newCommit, _, gErr := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: new(prTitle),
		Tree:    newTree,
		Parents: []*github.Commit{{SHA: github.Ptr(latestMainSHA)}},
	}, nil)
	if gErr != nil {
		return fmt.Errorf("creating rebase commit: %w", gErr)
	}

	_, _, uErr := gh.Git.UpdateRef(
		ctx,
		owner,
		repo,
		"refs/heads/"+prBranch,
		github.UpdateRef{
			SHA:   newCommit.GetSHA(),
			Force: new(true),
		},
	)
	if uErr != nil {
		return fmt.Errorf("force-pushing branch rebase: %w", uErr)
	}
	log.Info("successfully force-pushed branch to clean rebase commit", "pr", openPR.GetNumber())

	uncheckedBody := uncheckRebaseBox(openPR.GetBody())
	if uncheckedBody != openPR.GetBody() {
		if _, _, uErr := gh.PullRequests.Edit(ctx, owner, repo, openPR.GetNumber(), &github.PullRequest{
			Body: github.Ptr(uncheckedBody),
		}); uErr != nil {
			log.Warn("failed to uncheck rebase box in PR body", "error", uErr)
		}
	}

	return nil
}

func closeSupersededPRs(
	ctx context.Context,
	gh *github.Client,
	owner, repo, pkgName, fileAPIPath, prBranch, prTitle string,
	result versionResult,
	prExists bool,
	dryRun bool,
) (closedSuperseded []int, stillExists bool, err error) {
	log := clog.FromContext(ctx)
	stillExists = prExists

	var allPRs []*github.PullRequest
	err = withRetry(ctx, 3, func() error {
		var e error
		allPRs, _, e = gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{State: "open"})
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

		remoteFile, _, _, gErr := gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
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

		if dryRun {
			log.Info("DRY RUN: would close superseded PR and open new one",
				"closing_number", pr.GetNumber(), "new_version", result.Version)
			stillExists = false
			continue
		}

		if _, _, cErr := gh.Issues.CreateComment(ctx, owner, repo, pr.GetNumber(), &github.IssueComment{
			Body: github.Ptr(fmt.Sprintf(
				"This PR has been superseded by a newer version update: **%s**. Closing automatically.",
				prTitle)),
		}); cErr != nil {
			log.Warn("failed to post superseded comment", "number", pr.GetNumber(), "error", cErr)
		}
		if _, _, eErr := gh.PullRequests.Edit(ctx, owner, repo, pr.GetNumber(), &github.PullRequest{
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

func pushBranchContent(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, prBranch string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
	bot string,
) (newCommitSHA string, err error) {
	log := clog.FromContext(ctx)

	targetBranch := defaultBranch
	if branchExists {
		modified, mErr := isBranchModified(ctx, gh, owner, repo, defaultBranch, prBranch, bot)
		if mErr != nil {
			return "", fmt.Errorf("checking branch modification status: %w", mErr)
		}
		if modified {
			return "", errBranchModifiedByHuman
		}
		targetBranch = prBranch
	}

	var parentSHA string
	err = withRetry(ctx, 3, func() error {
		ref, _, e := gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+targetBranch)
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
		newCommitSHA, e = commitFileOnBranch(ctx, gh, owner, repo, prBranch, parentSHA, branchExists, relPath, content, commitMessage)
		return e
	})
	if err != nil {
		log.Debug("commit failed", "branch", prBranch, "error", err)
		return "", err
	}
	return newCommitSHA, nil
}

func commitFileOnBranch(
	ctx context.Context,
	gh *github.Client,
	owner, repo, prBranch, parentSHA string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
) (newCommitSHA string, err error) {
	parentCommit, _, err := gh.Git.GetCommit(ctx, owner, repo, parentSHA)
	if err != nil {
		return "", fmt.Errorf("getting parent commit %s: %w", parentSHA, err)
	}
	baseTreeSHA := parentCommit.GetTree().GetSHA()

	newTree, _, err := gh.Git.CreateTree(ctx, owner, repo, baseTreeSHA, []*github.TreeEntry{
		{
			Path:    new(relPath),
			Mode:    new("100644"),
			Type:    new("blob"),
			Content: new(string(content)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}

	newCommit, _, err := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: new(commitMessage),
		Tree:    &github.Tree{SHA: newTree.SHA},
		Parents: []*github.Commit{{SHA: new(parentSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("creating commit: %w", err)
	}

	if err := updateBranchRef(ctx, gh, owner, repo, prBranch, newCommit.GetSHA(), branchExists); err != nil {
		return "", err
	}

	return newCommit.GetSHA(), nil
}

func updateBranchRef(ctx context.Context, gh *github.Client, owner, repo, branch, newSHA string, branchExists bool) error {
	if !branchExists {
		_, _, err := gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{
			Ref: "refs/heads/" + branch,
			SHA: newSHA,
		})
		if err != nil && !isRefAlreadyExistsErr(err) {
			return fmt.Errorf("creating branch %s: %w", branch, err)
		}
		return nil
	}

	_, _, err := gh.Git.UpdateRef(ctx, owner, repo, "refs/heads/"+branch, github.UpdateRef{
		SHA:   newSHA,
		Force: new(true),
	})
	if err != nil {
		return fmt.Errorf("updating branch %s: %w", branch, err)
	}
	return nil
}

func createPullRequest(
	ctx context.Context,
	gh *github.Client,
	owner, repo, prBranch, defaultBranch, prTitle, prBody string,
) (string, error) {
	log := clog.FromContext(ctx)

	var newPR *github.PullRequest
	err := withRetry(ctx, 3, func() error {
		var e error
		newPR, _, e = gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
			Title: new(prTitle),
			Body:  new(prBody),
			Head:  new(prBranch),
			Base:  new(defaultBranch),
		})
		return e
	})
	if err != nil {
		if isPRAlreadyExistsErr(err) {
			log.Warn("PR was created concurrently by another run, treating as success")
			return "", nil
		}
		if is5xxErr(err) {
			log.Warn("server error creating PR, deleting branch so next run starts clean",
				"branch", prBranch, "error", err)
			if _, dErr := gh.Git.DeleteRef(ctx, owner, repo, "heads/"+prBranch); dErr != nil {
				log.Warn("failed to delete branch after failed PR creation", "error", dErr)
			}
		}
		return "", fmt.Errorf("creating PR: %w", err)
	}

	if _, _, lErr := gh.Issues.AddLabelsToIssue(ctx, owner, repo, newPR.GetNumber(),
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

func isBranchStale(ctx context.Context, gh *github.Client, owner, repo, defaultBranch, prBranch string) (bool, error) {
	comp, _, err := gh.Repositories.CompareCommits(ctx, owner, repo, defaultBranch, prBranch, nil)
	if err != nil {
		return false, fmt.Errorf("checking branch staleness: %w", err)
	}
	return comp.GetBehindBy() > 0, nil
}

func isBranchModified(ctx context.Context, gh *github.Client, owner, repo, defaultBranch, prBranch, bot string) (bool, error) {
	log := clog.FromContext(ctx)

	comp, _, err := gh.Repositories.CompareCommits(ctx, owner, repo, defaultBranch, prBranch, nil)
	if err != nil {
		return false, fmt.Errorf("comparing commits against base: %w", err)
	}
	if len(comp.Commits) == 0 {
		return false, nil
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

		return true, nil
	}

	return false, nil
}

func tryReuseClosedPR(ctx context.Context, gh *github.Client, owner, repo, prBranch string) (*github.PullRequest, error) {
	log := clog.FromContext(ctx)

	prs, _, err := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		State: "closed",
		Head:  fmt.Sprintf("%s:%s", owner, prBranch),
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
	if !hasAutomationLabel {
		log.Debug("closed PR on branch has no automation label, not reusing",
			"number", candidate.GetNumber())
		return nil, nil
	}
	if candidate.MergedAt != nil {
		return nil, nil
	}
	if candidate.ClosedAt == nil || time.Since(candidate.ClosedAt.Time) > reopenThreshold {
		log.Debug("closed PR too old to reopen, will create fresh",
			"number", candidate.GetNumber())
		return nil, nil
	}

	log.Info("found recently auto-closed PR for branch, reopening instead of creating new",
		"number", candidate.GetNumber(), "closed_at", candidate.GetClosedAt())

	reopened, _, err := gh.PullRequests.Edit(ctx, owner, repo, candidate.GetNumber(), &github.PullRequest{
		State: github.Ptr("open"),
	})
	if err != nil {
		log.Warn("failed to reopen autoclosed PR, will create new one instead",
			"number", candidate.GetNumber(), "error", err)
		return nil, nil
	}
	return reopened, nil
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func requiresUpToDateBranch(
	ctx context.Context,
	gh *github.Client,
	owner string,
	repo string,
	branch string,
) (bool, error) {
	protection, _, err := gh.Repositories.GetBranchProtection(
		ctx,
		owner,
		repo,
		branch,
	)
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

func shouldRebase(
	manualRebase bool,
	rebaseWhen string,
	hasConflict bool,
	stale bool,
	requireUpToDate bool,
) bool {
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
