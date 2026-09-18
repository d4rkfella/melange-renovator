package app

import (
	"fmt"
	"strings"
)

// RebasePolicy controls when melange-renovator rebases an existing PR
// branch onto the latest content.
type RebasePolicy string

const (
	RebaseAuto             RebasePolicy = "auto"
	RebaseBehindBaseBranch RebasePolicy = "behind-base-branch"
	RebaseConflicted       RebasePolicy = "conflicted"
	RebaseNever            RebasePolicy = "never"
)

func (p RebasePolicy) Valid() bool {
	switch p {
	case RebaseAuto, RebaseBehindBaseBranch, RebaseConflicted, RebaseNever:
		return true
	default:
		return false
	}
}

// RecreatePolicy controls whether a closed PR is recreated once a newer
// version becomes available.
type RecreatePolicy string

const (
	RecreateAuto   RecreatePolicy = "auto"
	RecreateAlways RecreatePolicy = "always"
	RecreateNever  RecreatePolicy = "never"
)

func (p RecreatePolicy) Valid() bool {
	switch p {
	case RecreateAuto, RecreateAlways, RecreateNever:
		return true
	default:
		return false
	}
}

// AWSOptions groups the S3 connection settings used for package-state
// persistence.
type AWSOptions struct {
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Endpoint  string
}

// Options holds every user-configurable setting for a melange-renovator
// run. It is built once from flags/environment in cmd/melange-renovator;
// nothing in internal/app reads flags or env vars directly.
type Options struct {
	Autodiscover       bool
	AutodiscoverFilter []string
	BaseDir            string
	DryRun             bool
	DashboardTitle     string
	Concurrency        int
	Token              string
	RebaseWhen         RebasePolicy
	RecreateWhen       RecreatePolicy
	ConfigFilePatterns []string
	IgnorePaths        []string
	AWS                AWSOptions
}

// Validate checks invariants flag parsing alone can't enforce. It is the
// single source of truth for "is this a runnable configuration", regardless
// of whether a value came from a flag or an environment variable.
func (o Options) Validate() error {
	var errs []string

	if o.Token == "" {
		errs = append(errs, "token is required")
	}
	if strings.ContainsAny(o.Token, " \t\n\r") {
		errs = append(errs, "token must not contain whitespace")
	}
	if o.Concurrency < 1 {
		errs = append(errs, "concurrency must be at least 1")
	}
	if !o.RebaseWhen.Valid() {
		errs = append(errs, fmt.Sprintf("rebase-when %q must be one of: auto, behind-base-branch, conflicted, never", o.RebaseWhen))
	}
	if !o.RecreateWhen.Valid() {
		errs = append(errs, fmt.Sprintf("recreate-when %q must be one of: auto, always, never", o.RecreateWhen))
	}
	if len(o.ConfigFilePatterns) == 0 {
		errs = append(errs, "at least one config-file-pattern is required")
	}
	if !o.DryRun && o.AWS.Bucket == "" {
		errs = append(errs, "s3-bucket is required unless --dry-run is set")
	}
	if o.DashboardTitle == "" {
		errs = append(errs, "dashboard-title must not be empty")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid options:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
