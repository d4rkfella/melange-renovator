// Package report defines the JSON shape melange-renovator prints to stdout.
// Treat this as a stable, external contract — other tooling may parse it —
// so prefer additive changes here.
package report

// VersionTransform is a single upstream-version rewrite rule.
type VersionTransform struct {
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

// Monitor describes how a package's upstream version is tracked.
type Monitor struct {
	Type                 string             `json:"type"`
	Identifier           string             `json:"identifier,omitempty"`
	UseTags              bool               `json:"useTags,omitempty"`
	EnablePreReleaseTags bool               `json:"enablePreReleaseTags,omitempty"`
	FilterPrefix         string             `json:"filterPrefix,omitempty"`
	FilterContains       string             `json:"filterContains,omitempty"`
	StripPrefix          string             `json:"stripPrefix,omitempty"`
	StripSuffix          string             `json:"stripSuffix,omitempty"`
	VersionTransforms    []VersionTransform `json:"versionTransforms,omitempty"`
	IgnoreRegexPatterns  []string           `json:"ignoreRegexPatterns,omitempty"`
}

// Schedule describes how often a package's update check is allowed to run.
type Schedule struct {
	Period string `json:"period,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Dep is the outcome of processing a single package config.
type Dep struct {
	DepName         string    `json:"depName"`
	PackageName     string    `json:"packageName"`
	Monitor         Monitor   `json:"monitor"`
	Schedule        *Schedule `json:"schedule,omitempty"`
	ClosedPRURL     string    `json:"closedPrUrl,omitempty"`
	CurrentVersion  string    `json:"currentVersion"`
	ResolvedTag     string    `json:"resolvedUpstreamTag,omitempty"`
	ResolvedVersion string    `json:"resolvedTransformedVersion,omitempty"`
	ResolvedCommit  string    `json:"resolvedCommitSha,omitempty"`
	UpdateAvailable bool      `json:"updateAvailable"`
	Skipped         bool      `json:"skipped"`
	SkipReason      string    `json:"skipReason,omitempty"`
	PRURL           string    `json:"prUrl,omitempty"`
	DryRun          bool      `json:"dryRun,omitempty"`
	Warnings        []string  `json:"warnings"`
}

// PackageFile groups every dependency found in one melange config file.
// Always exactly one Dep today (one package per file); kept plural for
// forward compatibility.
type PackageFile struct {
	PackageFile string `json:"packageFile"`
	Deps        []Dep  `json:"deps"`
}
