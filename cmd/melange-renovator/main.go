package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/app"
	"github.com/d4rkfella/melange-renovator/internal/report"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version   = "dev"
	commitSHA = "unknown"
	buildDate = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run builds the command tree and executes it. All process-exit decisions
// live in main; everything below this point returns errors normally.
func run(ctx context.Context) error {
	v := viper.New()
	v.SetEnvPrefix("RENOVATE")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	return newRootCommand(ctx, v).Execute()
}

func newRootCommand(ctx context.Context, v *viper.Viper) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "melange-renovator",
		Short:         "Discover and update melange package configs.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, log := setupLogger(ctx, v.GetString("log-level"))

			log.Info("starting melange-renovator", "version", version, "commit", commitSHA, "build_date", buildDate)
			log.Info("runtime environment", "GOOS", runtime.GOOS, "GOARCH", runtime.GOARCH, "GoVersion", runtime.Version())

			opts := optionsFromViper(v)
			if err := opts.Validate(); err != nil {
				return err
			}

			runner, cleanup, err := newRunner(ctx, opts)
			if err != nil {
				return fmt.Errorf("initializing: %w", err)
			}
			defer cleanup()

			rep, err := runner.Run(ctx)
			if err != nil {
				return err
			}
			return printReport(rep)
		},
	}

	rootCmd.Flags().Bool("autodiscover", false, "Discover repositories via the GitHub App installation instead of relying on a pre-checked-out repo")
	rootCmd.Flags().StringSlice("autodiscover-filter", nil, "Glob pattern(s) (owner/repo) to filter autodiscovered repositories")
	rootCmd.Flags().String("base-dir", "/tmp/renovate", "Base directory for repo clones and cache")
	rootCmd.Flags().String("log-level", "info", "Log level")
	rootCmd.Flags().Bool("dry-run", false, "Saves PR metadata to a local file and skips S3-dependent scheduling logic.")
	rootCmd.Flags().Int("concurrency", 10, "Number of parallel workers")
	rootCmd.Flags().String("s3-bucket", "", "AWS S3 bucket for state")
	rootCmd.Flags().String("aws-region", "us-east-1", "AWS region")
	rootCmd.Flags().String("aws-access-key", "", "AWS access key ID")
	rootCmd.Flags().String("aws-secret-key", "", "AWS secret access key")
	rootCmd.Flags().String("aws-endpoint", "", "Custom S3 endpoint URL")
	rootCmd.Flags().String("token", "", "GitHub token for API access")
	rootCmd.Flags().String("dependency-dashboard-title", "Renovate Dashboard", "Title of the dependency dashboard issue")
	rootCmd.Flags().String("rebase-when", "auto", "Rebase strategy for PRs (options: 'auto', 'behind-base-branch', 'conflicted', 'never')")
	rootCmd.Flags().String("recreate-when", "auto", "Recreate strategy for closed PRs (options: 'auto', 'always', 'never')")
	rootCmd.Flags().StringSlice("config-file-patterns", []string{`\.ya?ml$`}, "Regex patterns used to discover melange configuration files")
	rootCmd.Flags().StringSlice("ignore-paths", nil, "Glob patterns for paths to ignore during discovery")

	if err := v.BindPFlags(rootCmd.Flags()); err != nil {
		panic(err)
	}

	return rootCmd
}

func setupLogger(ctx context.Context, levelStr string) (context.Context, *clog.Logger) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelStr)); err != nil {
		level = slog.LevelInfo
	}
	logger := clog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	return clog.WithLogger(ctx, logger), logger
}

func optionsFromViper(v *viper.Viper) app.Options {
	return app.Options{
		Autodiscover:       v.GetBool("autodiscover"),
		AutodiscoverFilter: v.GetStringSlice("autodiscover-filter"),
		BaseDir:            v.GetString("base-dir"),
		DryRun:             v.GetBool("dry-run"),
		DashboardTitle:     v.GetString("dependency-dashboard-title"),
		Concurrency:        v.GetInt("concurrency"),
		Token:              v.GetString("token"),
		RebaseWhen:         app.RebasePolicy(v.GetString("rebase-when")),
		RecreateWhen:       app.RecreatePolicy(v.GetString("recreate-when")),
		ConfigFilePatterns: v.GetStringSlice("config-file-patterns"),
		IgnorePaths:        v.GetStringSlice("ignore-paths"),
		AWS: app.AWSOptions{
			Bucket:    v.GetString("s3-bucket"),
			Region:    v.GetString("aws-region"),
			AccessKey: v.GetString("aws-access-key"),
			SecretKey: v.GetString("aws-secret-key"),
			Endpoint:  v.GetString("aws-endpoint"),
		},
	}
}

func printReport(rep app.Report) error {
	var packages []report.PackageFile
	for _, r := range rep.Repos {
		packages = append(packages, r.Packages...)
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].PackageFile < packages[j].PackageFile
	})

	data, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
