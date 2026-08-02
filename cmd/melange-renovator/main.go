package main

import (
	"flag"

	renovator "github.com/d4rkfella/melange-renovator/internal/renovator"
)

func main() {
	logLevelFlag := flag.String("log-level", "info", "Log level")
	dryRunFlag := flag.Bool("dry-run", false, "Saves PR metadata to a local file if a new PR is to be opened and skips the schedule logic dependant on the S3 backend.")
	concurrencyFlag := flag.Int("concurrency", 5, "Number of parallel workers")

	s3BucketFlag := flag.String("s3-bucket", "", "AWS S3 bucket for state")
	awsRegionFlag := flag.String("aws-region", "us-east-1", "AWS region")
	awsAccessKeyFlag := flag.String("aws-access-key", "", "AWS access key ID")
	awsSecretKeyFlag := flag.String("aws-secret-key", "", "AWS secret access key")
	awsEndpointFlag := flag.String("aws-endpoint", "", "Custom S3 endpoint URL")

	flag.Parse()

	opts := renovator.Options{
		LogLevel:      *logLevelFlag,
		DryRun:        *dryRunFlag,
		Concurrency:   *concurrencyFlag,
		S3Bucket:      *s3BucketFlag,
		AWSRegion:     *awsRegionFlag,
		AWSAccessKey:  *awsAccessKeyFlag,
		AWSSecretKey:  *awsSecretKeyFlag,
		AWSEndpoint:   *awsEndpointFlag,
	}

	renovator.Run(opts)
}
