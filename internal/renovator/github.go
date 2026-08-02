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
	token string,
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

	if prExists {
		prURL = openPR.GetHTMLURL()

		repoInfo, _, rErr := gh.Repositories.Get(ctx, owner, repo)
		if rErr == nil {
			currentDefault := repoInfo.GetDefaultBranch()
			if openPR.GetBase().GetRef() != "" && openPR.GetBase().GetRef() != currentDefault && !dryRun {
				log.Info("PR base branch has drifted, retargeting",
					"pr", openPR.GetNumber(), "old_base", openPR.GetBase().GetRef(), "new_base", currentDefault)
				if _, _, uErr := gh.PullRequests.Edit(ctx, owner, repo, openPR.GetNumber(), &github.PullRequest{
					Base: &github.PullRequestBranch{Ref: github.Ptr(currentDefault)},
				}); uErr != nil {
					log.Warn("failed to retarget PR base branch", "error", uErr)
				}
			}
		}

		if sequential {
			log.Debug("Sequential mode: open PR already exists, skipping")
			return prURL, nil, nil
		}

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
		rebaseRequested := forceRebase || isRebaseRequested(openPR.GetBody())

		oldFP := fingerprint(remoteContent, openPR.GetTitle())
		newFP := fingerprint(string(content), prTitle)
		if oldFP == newFP && !rebaseRequested {
			log.Debug("content and title unchanged, nothing to do")
			return prURL, nil, nil
		}
		if rebaseRequested {
			log.Debug("rebase requested, forcing update despite unchanged content", "pr", openPR.GetNumber())
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

	repoInfo, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", nil, fmt.Errorf("getting repo info: %w", err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()
	cloneURL := repoInfo.GetCloneURL()

	pushed, err := pushFileWithRetry(ctx, cloneURL, token, defaultBranch, prBranch, branchExists, fileAPIPath, content, prTitle, 3)
	if err != nil {
		return "", nil, fmt.Errorf("pushing update to %s: %w", prBranch, err)
	}
	if !pushed {
		log.Debug("git reports nothing to commit", "branch", prBranch)
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
