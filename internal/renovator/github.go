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
	forceRebase bool,
) (string, []int, error) {
	log := clog.FromContext(ctx)
	var closedSuperseded []int

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("reading file: %w", err)
	}
	fileAPIPath := strings.TrimPrefix(filePath, "/github/workspace/")

	var branchExists bool
	err = withRetry(ctx, 3, func() error {
		_, resp, e := gh.Repositories.GetBranch(ctx, owner, repo, prBranch, 0)
		branchExists = e == nil
		if !branchExists && (resp == nil || resp.StatusCode != 404) {
			return e
		}
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("checking branch existence: %w", err)
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
		return "", nil, fmt.Errorf("checking for existing branch PRs: %w", err)
	}

	var openPR *github.PullRequest
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

	prExists := openPR != nil
	var prURL string

	repoInfo, _, rErr := gh.Repositories.Get(ctx, owner, repo)
	defaultBranch := "main"
	if rErr == nil {
		defaultBranch = repoInfo.GetDefaultBranch()
	}

	if prExists {
		prURL = openPR.GetHTMLURL()

		fullPR, _, pErr := gh.PullRequests.Get(ctx, owner, repo, openPR.GetNumber())
		if pErr == nil {
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

		if sequential {
			log.Debug("Sequential mode: open PR already exists, skipping")
			return prURL, nil, nil
		}

		// -------------------------------------------------------------------
		// RENOVATE DECISION GRAPH
		// -------------------------------------------------------------------

		rebaseWhen := "auto" // Options: "auto", "behind-base-branch", "conflicted", "never"

		// 1. Check for Conflicts
		hasConflict := isBranchConflicted(openPR)

		// 2. Check for Staleness (Behind Base Branch)
		stale, sErr := isBranchStale(ctx, gh, owner, repo, defaultBranch, prBranch)
		if sErr != nil {
			log.Warn("could not determine staleness", "error", sErr)
		}

		prBodyChecked := isRebaseRequested(openPR.GetBody())
		manualRebase := forceRebase || prBodyChecked

		staleRequiresRebase := stale && (rebaseWhen == "behind-base-branch")
		rebaseRequested := manualRebase || hasConflict || staleRequiresRebase

		log.Debug("rebase evaluation flags",
			"pr", openPR.GetNumber(),
			"rebase_requested", rebaseRequested,
			"manual_rebase", manualRebase,
			"force_rebase", forceRebase,
			"pr_body_checked", prBodyChecked,
			"has_conflict", hasConflict,
			"stale", stale,
			"stale_requires_rebase", staleRequiresRebase,
		)

		var remoteFile *github.RepositoryContent
		err = withRetry(ctx, 3, func() error {
			var e error
			remoteFile, _, _, e = gh.Repositories.GetContents(ctx, owner, repo, fileAPIPath,
				&github.RepositoryContentGetOptions{Ref: prBranch})
			return e
		})
		if err != nil {
			return "", nil, fmt.Errorf("fetching file from PR branch: %w", err)
		}

		remoteContent, _ := remoteFile.GetContent()

		// Compare fingerprints
		oldFP := fingerprint(remoteContent, openPR.GetTitle())
		newFP := fingerprint(string(content), prTitle)

		// Short-circuit: If content/title unchanged AND no rebase required, abort early
		if oldFP == newFP && !rebaseRequested {
			log.Debug("content and title unchanged and branch up to date, nothing to do")
			return prURL, nil, nil
		}

		if rebaseRequested {
			if manualRebase {
				log.Info("forcing branch rebase: user requested via checkbox or flag", "pr", openPR.GetNumber())
			} else if hasConflict {
				log.Info("forcing branch rebase: merge conflict detected with default branch", "pr", openPR.GetNumber())
			} else if staleRequiresRebase {
				log.Info("forcing branch rebase: branch is stale / behind default branch", "pr", openPR.GetNumber())
			}

			if !dryRun {
				prRef, _, gErr := gh.Git.GetRef(ctx, owner, repo, "heads/"+prBranch)
				if gErr != nil {
					return "", nil, fmt.Errorf("getting pr branch ref for rebase: %w", gErr)
				}
				oldPRSHA := prRef.GetObject().GetSHA()

				mainRef, _, gErr := gh.Git.GetRef(ctx, owner, repo, "heads/"+defaultBranch)
				if gErr != nil {
					return "", nil, fmt.Errorf("getting default branch ref for rebase: %w", gErr)
				}
				latestMainSHA := mainRef.GetObject().GetSHA()

				mainCommit, _, gErr := gh.Git.GetCommit(ctx, owner, repo, latestMainSHA)
				if gErr != nil {
					return "", nil, fmt.Errorf("getting main commit tree: %w", gErr)
				}

				newCommit, _, gErr := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
					Message: github.Ptr(fmt.Sprintf("Rebase branch with %s", defaultBranch)),
					Tree:    mainCommit.Tree,
					Parents: []*github.Commit{
						{SHA: github.Ptr(latestMainSHA)},
						{SHA: github.Ptr(oldPRSHA)},
					},
				}, nil)
				if gErr != nil {
					return "", nil, fmt.Errorf("creating rebase commit: %w", gErr)
				}

				_, _, uErr := gh.Git.UpdateRef(
					ctx,
					owner,
					repo,
					"refs/heads/"+prBranch,
					github.UpdateRef{
						SHA:   newCommit.GetSHA(),
						Force: github.Ptr(true),
					},
				)
				if uErr != nil {
					return "", nil, fmt.Errorf("force-resetting branch to default branch: %w", uErr)
				}
				log.Info("successfully force-reset branch to latest default branch commit", "pr", openPR.GetNumber())

				if prBodyChecked {
					uncheckedBody := uncheckRebaseBox(openPR.GetBody())
					if _, _, uErr := gh.PullRequests.Edit(ctx, owner, repo, openPR.GetNumber(), &github.PullRequest{
						Body: github.Ptr(uncheckedBody),
					}); uErr != nil {
						log.Warn("failed to uncheck rebase box in PR body", "error", uErr)
					}
				}
			}
		}
	}

	if !sequential {
		var allPRs []*github.PullRequest
		err = withRetry(ctx, 3, func() error {
			var e error
			allPRs, _, e = gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{State: "open"})
			return e
		})
		if err != nil {
			return "", nil, fmt.Errorf("listing all open PRs: %w", err)
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
				prExists = false
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
			prExists = false
		}
	}

	if dryRun {
		return "", closedSuperseded, nil
	}

	if _, err := commitFileWithRetry(ctx, gh, owner, repo, defaultBranch, prBranch, branchExists, fileAPIPath, content, prTitle); err != nil {
		if errors.Is(err, errBranchModifiedByHuman) {
			return prURL, closedSuperseded, nil
		}
		return "", nil, fmt.Errorf("committing update to %s: %w", prBranch, err)
	}

	if !prExists {
		var newPR *github.PullRequest
		createErr := withRetry(ctx, 3, func() error {
			var e error
			newPR, _, e = gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
				Title: github.Ptr(prTitle),
				Body:  github.Ptr(prBody),
				Head:  github.Ptr(prBranch),
				Base:  github.Ptr(defaultBranch),
			})
			return e
		})
		if createErr != nil {
			if isPRAlreadyExistsErr(createErr) {
				log.Warn("PR was created concurrently by another run, treating as success")
				return "", closedSuperseded, nil
			}
			if is5xxErr(createErr) {
				log.Warn("server error creating PR, deleting branch so next run starts clean",
					"branch", prBranch, "error", createErr)
				if _, dErr := gh.Git.DeleteRef(ctx, owner, repo, "heads/"+prBranch); dErr != nil {
					log.Warn("failed to delete branch after failed PR creation", "error", dErr)
				}
			}
			return "", nil, fmt.Errorf("creating PR: %w", createErr)
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

func commitFileWithRetry(
	ctx context.Context,
	gh *github.Client,
	owner, repo, defaultBranch, prBranch string,
	branchExists bool,
	relPath string,
	content []byte,
	commitMessage string,
) (newCommitSHA string, err error) {
	log := clog.FromContext(ctx)

	targetBranch := defaultBranch
	if branchExists {
		modified, mErr := isBranchModified(ctx, gh, owner, repo, defaultBranch, prBranch)
		if mErr != nil {
			return "", fmt.Errorf("checking branch modification status: %w", mErr)
		}
		if modified {
			log.Warn("branch has commits from someone other than this tool, leaving it untouched",
				"branch", prBranch)
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
			Path:    github.Ptr(relPath),
			Mode:    github.Ptr("100644"),
			Type:    github.Ptr("blob"),
			Content: github.Ptr(string(content)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating tree: %w", err)
	}

	newCommit, _, err := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: github.Ptr(commitMessage),
		Tree:    &github.Tree{SHA: newTree.SHA},
		Parents: []*github.Commit{{SHA: github.Ptr(parentSHA)}},
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
		Force: github.Ptr(true),
	})
	if err != nil {
		return fmt.Errorf("updating branch %s: %w", branch, err)
	}
	return nil
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

func isBranchModified(ctx context.Context, gh *github.Client, owner, repo, defaultBranch, prBranch string) (bool, error) {
	comp, _, err := gh.Repositories.CompareCommits(ctx, owner, repo, defaultBranch, prBranch, nil)
	if err != nil {
		return false, fmt.Errorf("comparing commits against base: %w", err)
	}
	if len(comp.Commits) == 0 {
		return false, nil
	}

	botActor := os.Getenv("GITHUB_ACTOR")
	if botActor == "" {
		botActor = "github-actions[bot]"
	}
	botEmail := os.Getenv("GIT_AUTHOR_EMAIL")

	for _, c := range comp.Commits {
		authorLogin := c.GetAuthor().GetLogin()
		gitAuthorEmail := c.GetCommit().GetAuthor().GetEmail()
		gitCommitterEmail := c.GetCommit().GetCommitter().GetEmail()

		if authorLogin != "" && strings.EqualFold(authorLogin, botActor) {
			continue
		}
		if botEmail != "" && (strings.EqualFold(gitAuthorEmail, botEmail) || strings.EqualFold(gitCommitterEmail, botEmail)) {
			continue
		}
		expectedDefaultEmail := fmt.Sprintf("%s@users.noreply.github.com", botActor)
		if strings.Contains(strings.ToLower(gitAuthorEmail), expectedDefaultEmail) ||
			strings.Contains(strings.ToLower(gitCommitterEmail), expectedDefaultEmail) {
			continue
		}

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
