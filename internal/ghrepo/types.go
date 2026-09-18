// Package ghrepo owns every GitHub interaction — reads and writes — for a
// single repository, plus the pull-request reconciliation logic that ties
// them together.
package ghrepo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PullRequest is a trimmed view of a GitHub pull request carrying only
// what reconciliation logic needs. Using this instead of *github.PullRequest
// throughout is what lets that logic be tested with plain struct literals.
type PullRequest struct {
	Number         int
	HTMLURL        string
	Title          string
	Body           string
	State          string
	BaseRef        string
	Mergeable      *bool
	MergeableState string
	MergedAt       *time.Time
	Labels         []string
}

func (pr *PullRequest) hasLabel(name string) bool {
	for _, l := range pr.Labels {
		if l == name {
			return true
		}
	}
	return false
}

// Commit is the subset of a comparison commit's metadata needed to decide
// whether a branch was modified by a human.
type Commit struct {
	SHA            string
	AuthorLogin    string
	AuthorEmail    string
	CommitterEmail string
}

// Comparison is a trimmed view of comparing one branch against another.
type Comparison struct {
	BehindBy int
	Commits  []Commit
}

func (c *Comparison) stale() bool { return c.BehindBy > 0 }

const automationLabel = "automated pr"

const prRebaseControl = "\n\n---\n\n - [ ] <!-- rebase-check -->If you want to rebase/retry this PR, check this box\n"

var prRebaseCheckboxRe = regexp.MustCompile(`- \[(?P<box>[xX])] <!-- rebase-check -->`)

func isRebaseRequested(body string) bool {
	return prRebaseCheckboxRe.MatchString(body)
}

func uncheckRebaseBox(body string) string {
	re := regexp.MustCompile(`(?i)- \[[xX]\](\s*.*(rebase|retry))`)
	return re.ReplaceAllString(body, "- [ ]$1")
}

func isBranchConflicted(pr *PullRequest) bool {
	if pr == nil {
		return false
	}
	if pr.Mergeable != nil && !*pr.Mergeable {
		return true
	}
	return pr.MergeableState == "dirty"
}

func buildPRMetadata(pkgName, version string) (branch, title, body string) {
	branch = fmt.Sprintf("update-%s", pkgName)
	title = fmt.Sprintf("%s/%s package update", pkgName, version)
	body = "<p align=\"center\">\n" +
		"  <img src=\"https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg\" />\n" +
		"</p>" + prRebaseControl
	return branch, title, body
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

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
