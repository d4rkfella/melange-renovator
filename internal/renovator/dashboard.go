package renovator

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v81/github"
)

func mdComment(s string) string {
	return fmt.Sprintf("<!-- %s -->", s)
}

func checkboxLine(marker string, checked bool) string {
	box := " "
	if checked {
		box = "x"
	}
	return fmt.Sprintf(" - [%s] %s", box, mdComment(marker))
}

func parseDashboardBody(body string) dashboardActions {
	actions := dashboardActions{
		RebasePR:   make(map[string]bool),
		RecreatePR: make(map[string]bool),
	}

	for marker := range allCheckedMarkers(body) {
		switch {
		case strings.HasPrefix(marker, "rebase-branch="):
			actions.RebasePR[strings.TrimPrefix(marker, "rebase-branch=")] = true
		case marker == "rebase-all-open-prs":
			actions.RebaseAll = true
		case strings.HasPrefix(marker, "recreate-branch="):
			actions.RecreatePR[strings.TrimPrefix(marker, "recreate-branch=")] = true
		case marker == "recreate-all-closed-prs":
			actions.RecreateAll = true
		}
	}
	return actions
}

func prBranchName(pkgName string) string {
	return "update-" + pkgName
}

func prNumberFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "pull" {
			return parts[i+1]
		}
	}

	return ""
}

func renderDashboardBody(report []renovatePackageFile) string {
	var errored, openPRs, upToDate, blocked []renovateDep
	for _, pf := range report {
		for _, d := range pf.Deps {
			switch {
			case d.ClosedPRUrl != "":
				blocked = append(blocked, d)
			case d.Skipped && d.SkipReason != "" && d.SkipReason != "not due per schedule":
				errored = append(errored, d)
			case d.PRUrl != "":
				openPRs = append(openPRs, d)
			default:
				upToDate = append(upToDate, d)
			}
		}
	}
	sortByName := func(s []renovateDep) {
		sort.Slice(s, func(i, j int) bool { return s[i].PackageName < s[j].PackageName })
	}
	sortByName(errored)
	sortByName(openPRs)
	sortByName(blocked)
	sortByName(upToDate)

	var b strings.Builder

	if len(errored) > 0 {
		b.WriteString("## Errored\n\n")
		b.WriteString("The following updates encountered an error and will be retried. To force a retry now, check a box below.\n\n")
		for _, d := range errored {
			b.WriteString(checkboxLine("retry-package="+d.PackageName, false))
			fmt.Fprintf(&b, " `%s` — %s\n", d.PackageName, d.SkipReason)
		}
		if len(errored) > 1 {
			b.WriteString(checkboxLine("retry-all-errored-prs", false))
			b.WriteString(" **Retry all errored updates at once**\n")
		}
		b.WriteString("\n")
	}

	if len(blocked) > 0 {
		b.WriteString("## Closed/Ignored\n\n")
		b.WriteString("The following updates are blocked by an existing closed PR. To recreate the PR, check a box below.\n\n")
		for _, d := range blocked {
			branch := prBranchName(d.PackageName)
			b.WriteString(checkboxLine("recreate-branch="+branch, false))
			if prNum := prNumberFromURL(d.ClosedPRUrl); prNum != "" {
				fmt.Fprintf(&b, " [%s/%s package update](../pull/%s)\n", d.PackageName, d.ResolvedVersion, prNum)
			} else {
				fmt.Fprintf(&b, " `%s/%s package update`\n", d.PackageName, d.ResolvedVersion)
			}
		}
		if len(blocked) > 1 {
			b.WriteString(checkboxLine("recreate-all-closed-prs", false))
			b.WriteString(" **Recreate all blocked PRs at once**\n")
		}
		b.WriteString("\n")
	}

	if len(openPRs) > 0 {
		b.WriteString("## Open\n\n")
		b.WriteString("The following updates have all been created. To force a retry/rebase of any, click on a checkbox below.\n\n")
		for _, d := range openPRs {
			branch := prBranchName(d.PackageName)
			b.WriteString(checkboxLine("rebase-branch="+branch, false))
			if prNum := prNumberFromURL(d.PRUrl); prNum != "" {
				fmt.Fprintf(&b, "[%s/%s package update](../pull/%s)\n", d.PackageName, d.ResolvedVersion, prNum)
			} else {
				fmt.Fprintf(&b, "[%s/%s package update](%s)\n", d.PackageName, d.ResolvedVersion, d.PRUrl)
			}
		}
		if len(openPRs) > 1 {
			b.WriteString(checkboxLine("rebase-all-open-prs", false))
			b.WriteString(" **Click on this checkbox to rebase all open PRs at once**\n")
		}
		b.WriteString("\n")
	}

	if len(openPRs) == 0 && len(errored) == 0 && len(blocked) == 0 {
		b.WriteString("This repository currently has no open or pending updates.\n\n")
	}

	b.WriteString("## Detected Dependencies\n\n")
	totalDeps := 0
	for _, pf := range report {
		totalDeps += len(pf.Deps)
	}
	if totalDeps == 0 {
		b.WriteString("None detected\n\n")
	} else {
		fmt.Fprintf(&b, "<details><summary>melange (%d)</summary>\n<blockquote>\n\n", totalDeps)
		sortedReport := append([]renovatePackageFile{}, report...)
		sort.Slice(sortedReport, func(i, j int) bool { return sortedReport[i].PackageFile < sortedReport[j].PackageFile })
		for _, pf := range sortedReport {
			fmt.Fprintf(&b, "<details><summary>%s</summary>\n\n", pf.PackageFile)
			for _, d := range pf.Deps {
				version := d.CurrentVersion
				if version == "" {
					version = "unknown version"
				}
				line := fmt.Sprintf(" - `%s %s`", d.DepName, version)
				if d.UpdateAvailable && d.ResolvedVersion != "" {
					line += fmt.Sprintf(" → [Updates: `%s`]", d.ResolvedVersion)
				}
				b.WriteString(line)
				b.WriteString("\n")
			}
			b.WriteString("\n</details>\n\n")
		}
		b.WriteString("</blockquote>\n</details>\n\n")
	}

	return b.String()
}

func (rm *repoManager) readDashboard(ctx context.Context) (issueNumber int, startBody string, checks dashboardActions, err error) {
	issues, _, err := rm.gh.Issues.ListByRepo(ctx, rm.owner, rm.repo, &github.IssueListByRepoOptions{
		State: "open",
	})
	if err != nil {
		return 0, "", dashboardActions{}, fmt.Errorf("listing dashboard issue: %w", err)
	}
	for _, iss := range issues {
		if iss.GetTitle() == dashboardTitle {
			return iss.GetNumber(), iss.GetBody(), parseDashboardBody(iss.GetBody()), nil
		}
	}
	return 0, "", dashboardActions{}, nil
}

func (rm *repoManager) ensureDependencyDashboard(ctx context.Context, report []renovatePackageFile, autoclose bool, startBody string) error {
	log := clog.FromContext(ctx)

	hasErrors := false
	hasOpenPRs := false
	hasBlocked := false
	for _, pf := range report {
		for _, d := range pf.Deps {
			if d.Skipped && d.SkipReason != "" && d.SkipReason != "not due per schedule" {
				hasErrors = true
			}
			if d.PRUrl != "" {
				hasOpenPRs = true
			}
			if d.ClosedPRUrl != "" {
				hasBlocked = true
			}
		}
	}

	issues, _, err := rm.gh.Issues.ListByRepo(ctx, rm.owner, rm.repo, &github.IssueListByRepoOptions{
		State: "all",
	})
	if err != nil {
		return fmt.Errorf("listing issues: %w", err)
	}
	var matching []*github.Issue
	for _, iss := range issues {
		if iss.GetTitle() == dashboardTitle {
			matching = append(matching, iss)
		}
	}
	var existing *github.Issue
	for _, iss := range matching {
		if iss.GetState() != "open" {
			continue
		}
		if existing == nil {
			existing = iss
			continue
		}
		if cErr := rm.editIssue(ctx, iss.GetNumber(), &github.IssueRequest{
			State: github.Ptr("closed"),
		}); cErr != nil {
			log.Warn("failed to close duplicate dashboard issue", "number", iss.GetNumber(), "error", cErr)
		}
	}
	if existing == nil {
		for _, iss := range matching {
			if existing == nil || iss.GetNumber() > existing.GetNumber() {
				existing = iss
			}
		}
	}

	if autoclose && !hasErrors && !hasOpenPRs && !hasBlocked {
		if existing == nil || existing.GetState() == "closed" {
			return nil
		}
		return rm.editIssue(ctx, existing.GetNumber(), &github.IssueRequest{
			State: github.Ptr("closed"),
		})
	}

	if existing == nil && !hasErrors && !hasOpenPRs && !hasBlocked {
		return nil
	}

	freshBody := renderDashboardBody(report)

	if existing != nil && existing.GetState() == "open" && freshBody == startBody {
		log.Debug("No changes to dependency dashboard issue needed")
		return nil
	}

	if existing != nil {
		liveChecked := allCheckedMarkers(existing.GetBody())
		startChecked := allCheckedMarkers(startBody)
		for marker := range liveChecked {
			if startChecked[marker] {
				continue
			}
			uncheckedPrefix := checkboxLine(marker, false)
			checkedPrefix := checkboxLine(marker, true)
			if strings.Contains(freshBody, uncheckedPrefix) {
				freshBody = strings.Replace(freshBody, uncheckedPrefix, checkedPrefix, 1)
				log.Debug("preserving mid-run checkbox check into next dashboard body", "marker", marker)
			}
		}
	}

	body := freshBody

	if existing == nil {
		return rm.createIssue(ctx, dashboardTitle, body)
	}

	req := &github.IssueRequest{Body: github.Ptr(body)}
	if existing.GetState() == "closed" {
		req.State = github.Ptr("open")
	}
	return rm.editIssue(ctx, existing.GetNumber(), req)
}

func isRebaseRequested(body string) bool {
	return prRebaseCheckboxRe.MatchString(body)
}

func uncheckRebaseBox(body string) string {
	re := regexp.MustCompile(`(?i)- \[[xX]\](\s*.*(rebase|retry))`)
	return re.ReplaceAllString(body, "- [ ]$1")
}

func allCheckedMarkers(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range anyCheckboxRe.FindAllStringSubmatch(body, -1) {
		if m[1] == "x" || m[1] == "X" {
			out[m[2]] = true
		}
	}
	return out
}

func shouldRunSchedule(s *config.Schedule, lastChecked time.Time) bool {
	if s == nil {
		return true
	}

	period := strings.ToLower(string(s.Period))
	if period == "" || period == "none" {
		return true
	}

	now := time.Now()
	switch period {
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
