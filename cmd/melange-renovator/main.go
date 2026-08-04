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

	rootCmd.Flags().String("log-level", "info", "Log level")
	rootCmd.Flags().Bool("dry-run", false, "Saves PR metadata to a local file and skips S3-dependent scheduling logic.")
	rootCmd.Flags().Int("concurrency", 10, "Number of parallel workers")
	rootCmd.Flags().String("s3-bucket", "", "AWS S3 bucket for state")
	rootCmd.Flags().String("aws-region", "us-east-1", "AWS region")
	rootCmd.Flags().String("aws-access-key", "", "AWS access key ID")
	rootCmd.Flags().String("aws-secret-key", "", "AWS secret access key")
	rootCmd.Flags().String("aws-endpoint", "", "Custom S3 endpoint URL")
	rootCmd.Flags().String("token", "", "GitHub token for API access")

	for _, key := range []string{"log-level", "dry-run", "concurrency", "s3-bucket", "aws-region", "aws-access-key", "aws-secret-key", "aws-endpoint"} {
		if err := v.BindPFlag(key, rootCmd.Flags().Lookup(key)); err != nil {
			panic(err)
		}
	}

	v.SetDefault("log-level", "info")
	v.SetDefault("dry-run", false)
	v.SetDefault("concurrency", 10)
	v.SetDefault("aws-region", "us-east-1")

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
		token = os.Getenv("RENOVATE_TOKEN")
		if token != "" {
			v.Set("token", token)
		}
	}

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
		LogLevel:     v.GetString("log-level"),
		DryRun:       v.GetBool("dry-run"),
		Concurrency:  v.GetInt("concurrency"),
		S3Bucket:     v.GetString("s3-bucket"),
		AWSRegion:    v.GetString("aws-region"),
		AWSAccessKey: v.GetString("aws-access-key"),
		AWSSecretKey: v.GetString("aws-secret-key"),
		AWSEndpoint:  v.GetString("aws-endpoint"),
		Token:        v.GetString("token"),
	}
}
