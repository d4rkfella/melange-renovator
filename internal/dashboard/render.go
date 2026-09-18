package dashboard

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/d4rkfella/melange-renovator/internal/report"
)

var anyCheckboxRe = regexp.MustCompile(`- \[( |x)] <!-- ([^>]+?) -->`)

func mdComment(s string) string { return fmt.Sprintf("<!-- %s -->", s) }

func checkboxLine(marker string, checked bool) string {
	box := " "
	if checked {
		box = "x"
	}
	return fmt.Sprintf(" - [%s] %s", box, mdComment(marker))
}

func prBranchName(pkgName string) string { return "update-" + pkgName }

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

func allCheckedMarkers(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range anyCheckboxRe.FindAllStringSubmatch(body, -1) {
		if m[1] == "x" {
			out[m[2]] = true
		}
	}
	return out
}

// parseDashboardBody extracts manual actions from a dashboard issue body's
// checked checkboxes.
func parseDashboardBody(body string) Actions {
	actions := Actions{
		RebasePR:     make(map[string]bool),
		RecreatePR:   make(map[string]bool),
		RetryPackage: make(map[string]bool),
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
		case strings.HasPrefix(marker, "retry-package="):
			actions.RetryPackage[strings.TrimPrefix(marker, "retry-package=")] = true
		case marker == "retry-all-errored-prs":
			actions.RetryAll = true
		}
	}
	return actions
}

// renderBody renders the full dashboard issue body from a run's report.
func renderBody(packages []report.PackageFile) string {
	var errored, openPRs, upToDate, blocked []report.Dep
	for _, pf := range packages {
		for _, d := range pf.Deps {
			switch {
			case d.ClosedPRURL != "":
				blocked = append(blocked, d)
			case d.Skipped && d.SkipReason != "" && d.SkipReason != "not due per schedule":
				errored = append(errored, d)
			case d.PRURL != "":
				openPRs = append(openPRs, d)
			default:
				upToDate = append(upToDate, d)
			}
		}
	}
	sortByName := func(s []report.Dep) {
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
			if prNum := prNumberFromURL(d.ClosedPRURL); prNum != "" {
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
			if prNum := prNumberFromURL(d.PRURL); prNum != "" {
				fmt.Fprintf(&b, "[%s/%s package update](../pull/%s)\n", d.PackageName, d.ResolvedVersion, prNum)
			} else {
				fmt.Fprintf(&b, "[%s/%s package update](%s)\n", d.PackageName, d.ResolvedVersion, d.PRURL)
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
	for _, pf := range packages {
		totalDeps += len(pf.Deps)
	}
	if totalDeps == 0 {
		b.WriteString("None detected\n\n")
	} else {
		fmt.Fprintf(&b, "<details><summary>melange (%d)</summary>\n<blockquote>\n\n", totalDeps)
		sorted := append([]report.PackageFile{}, packages...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].PackageFile < sorted[j].PackageFile })
		for _, pf := range sorted {
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

func preserveMidRunChecks(freshBody, liveBody, startBody string) string {
	liveChecked := allCheckedMarkers(liveBody)
	startChecked := allCheckedMarkers(startBody)
	for marker := range liveChecked {
		if startChecked[marker] {
			continue
		}
		unchecked := checkboxLine(marker, false)
		checked := checkboxLine(marker, true)
		freshBody = strings.Replace(freshBody, unchecked, checked, 1)
	}
	return freshBody
}

func summarize(packages []report.PackageFile) (hasErrors, hasOpenPRs, hasBlocked bool) {
	for _, pf := range packages {
		for _, d := range pf.Deps {
			if d.Skipped && d.SkipReason != "" && d.SkipReason != "not due per schedule" {
				hasErrors = true
			}
			if d.PRURL != "" {
				hasOpenPRs = true
			}
			if d.ClosedPRURL != "" {
				hasBlocked = true
			}
		}
	}
	return
}
