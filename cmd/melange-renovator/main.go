package main

import (
	"fmt"
	"os"
	"strings"

	renovator "github.com/d4rkfella/melange-renovator/internal/renovator"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	v := viper.New()
	v.SetEnvPrefix("MELANGE_RENOVATOR")
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
			renovator.Run(newOptionsFromViper(v))
			return nil
		},
	}

	rootCmd.Flags().String("log-level", "info", "Log level")
	rootCmd.Flags().Bool("dry-run", false, "Saves PR metadata to a local file and skips S3-dependent scheduling logic.")
	rootCmd.Flags().Int("concurrency", 5, "Number of parallel workers")
	rootCmd.Flags().String("s3-bucket", "", "AWS S3 bucket for state")
	rootCmd.Flags().String("aws-region", "us-east-1", "AWS region")
	rootCmd.Flags().String("aws-access-key", "", "AWS access key ID")
	rootCmd.Flags().String("aws-secret-key", "", "AWS secret access key")
	rootCmd.Flags().String("aws-endpoint", "", "Custom S3 endpoint URL")

	for _, key := range []string{"log-level", "dry-run", "concurrency", "s3-bucket", "aws-region", "aws-access-key", "aws-secret-key", "aws-endpoint"} {
		if err := v.BindPFlag(key, rootCmd.Flags().Lookup(key)); err != nil {
			panic(err)
		}
	}

	v.SetDefault("log-level", "info")
	v.SetDefault("dry-run", false)
	v.SetDefault("concurrency", 5)
	v.SetDefault("aws-region", "us-east-1")

	return rootCmd
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
	}
}
