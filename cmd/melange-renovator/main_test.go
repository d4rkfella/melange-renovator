package main

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestNewOptionsFromViper_UsesEnvValues(t *testing.T) {
	t.Setenv("MELANGE_RENOVATOR_DRY_RUN", "true")
	t.Setenv("MELANGE_RENOVATOR_CONCURRENCY", "9")
	t.Setenv("MELANGE_RENOVATOR_S3_BUCKET", "demo-bucket")

	v := viper.New()
	v.SetEnvPrefix("MELANGE_RENOVATOR")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	opts := newOptionsFromViper(v)

	if !opts.DryRun {
		t.Fatal("expected dry-run option to be loaded from env")
	}
	if opts.Concurrency != 9 {
		t.Fatalf("expected concurrency 9 from env, got %d", opts.Concurrency)
	}
	if opts.S3Bucket != "demo-bucket" {
		t.Fatalf("expected s3 bucket from env, got %q", opts.S3Bucket)
	}
}
