// Package versioning resolves the latest eligible upstream version for a
// melange package, across every monitor type melange-renovator supports
// (GitHub, raw git, OCI, release-monitoring.org).
package versioning

import (
	"fmt"
	"regexp"

	"chainguard.dev/melange/pkg/config"
)

// Transform is a single, pre-compiled upstream-version rewrite rule.
type Transform struct {
	Re      *regexp.Regexp
	Replace string
}

// Patterns groups every pre-compiled regex a package config supplies for
// filtering and rewriting upstream version strings. Compiling once up
// front (via CompilePatterns) means a malformed regex is reported as a
// per-package config error instead of failing silently on every tag.
type Patterns struct {
	Ignore     []*regexp.Regexp
	Transforms []Transform
}

// CompilePatterns compiles the ignore-regex and version-transform patterns
// from a package config. It never partially succeeds: any invalid pattern
// fails the whole call.
func CompilePatterns(cfg *config.Configuration) (Patterns, error) {
	ignore := make([]*regexp.Regexp, 0, len(cfg.Update.IgnoreRegexPatterns))
	for _, p := range cfg.Update.IgnoreRegexPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return Patterns{}, fmt.Errorf("invalid ignore pattern regex %q: %w", p, err)
		}
		ignore = append(ignore, re)
	}

	transforms := make([]Transform, 0, len(cfg.Update.VersionTransform))
	for _, t := range cfg.Update.VersionTransform {
		re, err := regexp.Compile(t.Match)
		if err != nil {
			return Patterns{}, fmt.Errorf("invalid version transform regex %q: %w", t.Match, err)
		}
		transforms = append(transforms, Transform{Re: re, Replace: t.Replace})
	}

	return Patterns{Ignore: ignore, Transforms: transforms}, nil
}
