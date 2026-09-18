// Package discover finds repositories and melange package configs for
// melange-renovator to process: autodiscovering repos via a GitHub App
// installation (and cloning them locally), and scanning a local checkout
// for eligible melange configs.
package discover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/chainguard-dev/clog"
	"github.com/d4rkfella/melange-renovator/internal/app"
)

// Scanner implements app.ConfigScanner by walking a local checkout.
type Scanner struct{}

func (Scanner) Scan(ctx context.Context, root string, filePatterns, ignorePaths []string) ([]app.ConfigFile, error) {
	log := clog.FromContext(ctx)

	patterns := make([]*regexp.Regexp, 0, len(filePatterns))
	for _, p := range filePatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid config file pattern %q: %w", p, err)
		}
		patterns = append(patterns, re)
	}

	var found []app.ConfigFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Warn("directory walk error", "path", path, "error", err)
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			log.Warn("failed calculating relative path", "path", path, "error", err)
			return nil
		}

		if shouldIgnorePath(relPath, ignorePaths) {
			if d.IsDir() {
				log.Debug("skipping ignored directory", "path", relPath)
				return filepath.SkipDir
			}
			log.Debug("skipping ignored file", "path", relPath)
			return nil
		}

		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if !matchesAny(relPath, patterns) {
			return nil
		}

		// Parsed here only to check Update.Enabled; internal/process parses
		// the file again to get the full config it needs for version
		// resolution. That's a deliberate small duplication — it keeps
		// app.ConfigFile from having to carry a parsed *config.Configuration
		// (and app from importing melange's config package), and melange
		// YAML files are small enough that parsing twice is not worth the
		// coupling it would save.
		cfg, err := config.ParseConfiguration(ctx, path)
		if err != nil {
			log.Debug("failed to parse configuration file, skipping", "path", relPath, "error", err)
			return nil
		}
		if !cfg.Update.Enabled {
			log.Debug("skipping config: updates are disabled", "path", relPath)
			return nil
		}

		found = append(found, app.ConfigFile{Path: path, RepoRelPath: filepath.ToSlash(relPath)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}

	log.Debug("matched melange configs", "count", len(found))
	return found, nil
}

func matchesAny(path string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(path) {
			return true
		}
	}
	return false
}

func shouldIgnorePath(path string, patterns []string) bool {
	for _, p := range patterns {
		if matched, err := doublestar.Match(p, path); err == nil && matched {
			return true
		}
	}
	return false
}
