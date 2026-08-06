package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/chainguard-dev/clog"
	renovator "github.com/d4rkfella/melange-renovator/internal/renovator"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version   = "dev"
	commitSHA = "unknown"
	buildDate = "unknown"
)

func main() {
	v := viper.New()
	v.SetEnvPrefix("RENOVATE")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	rootCmd := newRootCommand(v)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand(v *viper.Viper) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "melange-renovator",
		Short:         "Discover and update melange package configs.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var logLevel slog.Level
			if err := logLevel.UnmarshalText([]byte(v.GetString("log-level"))); err != nil {
				logLevel = slog.LevelInfo
			}

			logger := clog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
			ctx := clog.WithLogger(context.Background(), logger)
			log := clog.FromContext(ctx)

			log.Info("Starting melange-renovator",
				"version", version,
				"commit", commitSHA,
				"build_date", buildDate,
			)
			log.Info("Runtime Environment",
				"GOOS", runtime.GOOS,
				"GOARCH", runtime.GOARCH,
				"GoVersion", runtime.Version(),
			)

			if err := validateAndGetToken(v); err != nil {
				log.Error("Token validation failed", "error", err)
				return err
			}

			renovator.RunContext(ctx, newOptionsFromViper(v))
			return nil
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
	rootCmd.Flags().String("rebase-when", "auto", "Rebase strategy for PRs (options: 'auto', 'behind-base-branch', 'conflicted', 'never')")
	rootCmd.Flags().StringSlice("config-file-patterns", []string{`\.ya?ml$`}, "Regex patterns used to discover melange configuration files")
	rootCmd.Flags().StringSlice("ignore-paths", nil, "Glob patterns for paths to ignore during discovery")

	if err := v.BindPFlags(rootCmd.Flags()); err != nil {
		panic(err)
	}

	return rootCmd
}

type TokenValidationError struct {
	Message string
}

func (e TokenValidationError) Error() string {
	return e.Message
}

func validateAndGetToken(v *viper.Viper) error {
	token := v.GetString("token")

	if token == "" {
		return TokenValidationError{
			Message: "'token' MUST be passed using the --token flag or the 'RENOVATE_TOKEN' environment variable",
		}
	}

	if containsWhitespace(token) {
		return TokenValidationError{
			Message: "Token MUST NOT contain whitespace",
		}
	}

	return nil
}

func containsWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func newOptionsFromViper(v *viper.Viper) renovator.Options {
	return renovator.Options{
		Autodiscover:       v.GetBool("autodiscover"),
		AutodiscoverFilter: v.GetStringSlice("autodiscover-filter"),
		BaseDir:            v.GetString("base-dir"),
		LogLevel:           v.GetString("log-level"),
		DryRun:             v.GetBool("dry-run"),
		Concurrency:        v.GetInt("concurrency"),
		S3Bucket:           v.GetString("s3-bucket"),
		AWSRegion:          v.GetString("aws-region"),
		AWSAccessKey:       v.GetString("aws-access-key"),
		AWSSecretKey:       v.GetString("aws-secret-key"),
		AWSEndpoint:        v.GetString("aws-endpoint"),
		Token:              v.GetString("token"),
		RebaseWhen:         v.GetString("rebase-when"),
		ConfigFilePatterns: v.GetStringSlice("config-file-patterns"),
		IgnorePaths:        v.GetStringSlice("ignore-paths"),
	}
}
