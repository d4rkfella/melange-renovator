package renovator

import (
	"regexp"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"github.com/go-git/go-git/v5/plumbing"
)

const reopenThreshold = 7 * 24 * time.Hour

const dashboardTitle = "Renovate Dashboard"

const prRebaseControl = "\n\n---\n\n - [ ] <!-- rebase-check -->If you want to force a re-push of this PR (e.g. to retrigger CI), check this box\n"

type packageState struct {
	LastVersion string    `json:"last_version"`
	LastChecked time.Time `json:"last_checked"`
}

type discoveredConfig struct {
	Path   string
	Config *config.Configuration
}

type dashboardChecks struct {
	RetryPackage map[string]bool
	RebasePR     map[string]bool
	RetryAll     bool
	RebaseAll    bool
}

type awsOptions struct {
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Endpoint  string
}

type versionResult struct {
	Version        string
	UpstreamTag    string
	CommitSHA      string
	TagsConsidered int
	TagsSkipped    int
}

type tagRef struct {
	Name string
	Hash plumbing.Hash
}

type compiledVersionTransform struct {
	Re      *regexp.Regexp
	Replace string
}

type versionCandidate struct {
	Upstream    string
	Transformed string
	ApkVer      apk.Version
}

type resolveStats struct {
	Total   int
	Skipped int
}

type compiledPatterns struct {
	IgnorePatterns    []*regexp.Regexp
	VersionTransforms []compiledVersionTransform
}

type vtInfo struct {
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

type monitorConfig struct {
	Type                 string   `json:"type"`
	Identifier           string   `json:"identifier,omitempty"`
	UseTags              bool     `json:"useTags,omitempty"`
	EnablePreReleaseTags bool     `json:"enablePreReleaseTags,omitempty"`
	FilterPrefix         string   `json:"filterPrefix,omitempty"`
	FilterContains       string   `json:"filterContains,omitempty"`
	StripPrefix          string   `json:"stripPrefix,omitempty"`
	StripSuffix          string   `json:"stripSuffix,omitempty"`
	VersionTransforms    []vtInfo `json:"versionTransforms,omitempty"`
	IgnoreRegexPatterns  []string `json:"ignoreRegexPatterns,omitempty"`
}

type scheduleInfo struct {
	Period string `json:"period,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type renovateDep struct {
	DepName         string        `json:"depName"`
	PackageName     string        `json:"packageName"`
	Monitor         monitorConfig `json:"monitor"`
	Schedule        *scheduleInfo `json:"schedule,omitempty"`
	CurrentVersion  string        `json:"currentVersion"`
	ResolvedTag     string        `json:"resolvedUpstreamTag,omitempty"`
	ResolvedVersion string        `json:"resolvedTransformedVersion,omitempty"`
	ResolvedCommit  string        `json:"resolvedCommitSha,omitempty"`
	FixedVersion    string        `json:"fixedVersion,omitempty"`
	UpdateAvailable bool          `json:"updateAvailable"`
	Skipped         bool          `json:"skipped"`
	SkipReason      string        `json:"skipReason,omitempty"`
	PRUrl           string        `json:"prUrl,omitempty"`
	DryRun          bool          `json:"dryRun,omitempty"`
	Warnings        []string      `json:"warnings"`
}

type renovatePackageFile struct {
	PackageFile string        `json:"packageFile"`
	Deps        []renovateDep `json:"deps"`
}

var anyCheckboxRe = regexp.MustCompile(`- \[( |x)] <!-- ([^>]+?) -->`)
var prRebaseCheckboxRe = regexp.MustCompile(`- \[(?P<box>[\sx])] <!-- rebase-check -->`)
