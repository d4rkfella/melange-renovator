package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/d4rkfella/melange-renovator/internal/app"
	"github.com/d4rkfella/melange-renovator/internal/dashboard"
	"github.com/d4rkfella/melange-renovator/internal/discover"
	"github.com/d4rkfella/melange-renovator/internal/ghrepo"
	"github.com/d4rkfella/melange-renovator/internal/process"
	"github.com/d4rkfella/melange-renovator/internal/repo"
	"github.com/d4rkfella/melange-renovator/internal/state"
	"github.com/d4rkfella/melange-renovator/internal/versioning"
	"github.com/google/go-github/v81/github"
)

// newRunner wires the real, production implementations of every interface
// app.Runner depends on from validated Options. It is the only place in
// this codebase allowed to know about concrete infrastructure.
func newRunner(ctx context.Context, opts app.Options) (runner *app.Runner, cleanup func(), err error) {
	gh := github.NewClient(nil).WithAuthToken(opts.Token)

	var awsOptFns []func(*awscfg.LoadOptions) error
	if opts.AWS.Region != "" {
		awsOptFns = append(awsOptFns, awscfg.WithRegion(opts.AWS.Region))
	}
	if opts.AWS.AccessKey != "" && opts.AWS.SecretKey != "" {
		creds := credentials.NewStaticCredentialsProvider(opts.AWS.AccessKey, opts.AWS.SecretKey, "")
		awsOptFns = append(awsOptFns, awscfg.WithCredentialsProvider(creds))
	}
	awsConf, err := awscfg.LoadDefaultConfig(ctx, awsOptFns...)
	if err != nil {
		return nil, nil, fmt.Errorf("loading AWS config: %w", err)
	}
	s3Client := s3.NewFromConfig(awsConf, func(o *s3.Options) {
		if opts.AWS.Endpoint != "" {
			o.BaseEndpoint = aws.String(opts.AWS.Endpoint)
		}
	})

	var store state.Store = state.S3Store{Client: s3Client, Bucket: opts.AWS.Bucket}
	var issueClient dashboard.IssueClient = dashboard.GitHubIssueClient{GH: gh}
	if opts.DryRun {
		store = state.DryRunStore{Store: store}
		issueClient = dashboard.DryRunIssueClient{IssueClient: issueClient}
	}

	releaseFetcher, releaseCleanup := versioning.NewChromeReleaseFetcher(ctx, os.Getenv("RELEASE_MONITOR_TOKEN"))

	proc := &process.Processor{
		GitHubAPI:      gh,
		GitSources:     versioning.NewGitRemote(),
		OCISources:     versioning.NewOCITagLister(),
		ReleaseSources: releaseFetcher,
		State:          store,
		DryRun:         opts.DryRun,
		Clock:          app.RealClock{},
	}

	runner = &app.Runner{
		Discoverer: discover.NewDiscoverer(discover.GitHubInstallationLister{GH: gh}, opts.Token, opts.AutodiscoverFilter),
		Scanner:    discover.Scanner{},
		Inspector:  repoInspector{gh: gh},
		Identity:   identityResolver{gh: gh},
		Dashboard:  dashboard.NewManager(issueClient),
		Processor:  proc,
		Clock:      app.RealClock{},
		Options:    opts,
	}
	return runner, releaseCleanup, nil
}

// repoInspector and identityResolver are tiny adapters from ghrepo's
// owner/repo-parameterized functions to app's Repo-based interfaces.
type repoInspector struct{ gh *github.Client }

func (r repoInspector) DefaultBranch(ctx context.Context, repo repo.Identifier) (string, error) {
	return ghrepo.NewClient(r.gh, repo.Owner, repo.Name, false).DefaultBranch(ctx)
}

type identityResolver struct{ gh *github.Client }

func (r identityResolver) BotLogin(ctx context.Context) (string, error) {
	return ghrepo.BotLogin(ctx, r.gh)
}
