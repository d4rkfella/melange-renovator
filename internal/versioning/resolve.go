package versioning

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
)

// Candidate is a single upstream version string that survived filtering
// and parsed successfully as a valid APK version.
type Candidate struct {
	Upstream    string
	Transformed string
	apkVer      apk.Version
}

// Stats summarizes how many candidate versions were considered vs skipped,
// surfaced to the user as a warning when the skip count is non-zero.
type Stats struct {
	Total   int
	Skipped int
}

func shouldSkip(ctx context.Context, tag string, vh config.VersionHandler, ignore []*regexp.Regexp) bool {
	log := clog.FromContext(ctx)

	if p := vh.GetFilterPrefix(); p != "" && !strings.HasPrefix(tag, p) {
		log.Debug("version skipped: does not match filter-prefix", "tag", tag, "filter_prefix", p)
		return true
	}
	if c := vh.GetFilterContains(); c != "" && !strings.Contains(tag, c) {
		log.Debug("version skipped: does not match filter-contains", "tag", tag, "filter_contains", c)
		return true
	}
	for _, re := range ignore {
		if re.MatchString(tag) {
			log.Debug("version skipped: matched ignore-regex-patterns entry", "tag", tag, "pattern", re.String())
			return true
		}
	}
	return false
}

func applyTransforms(upstream string, vh config.VersionHandler, transforms []Transform) string {
	out := strings.TrimPrefix(upstream, vh.GetStripPrefix())
	out = strings.TrimSuffix(out, vh.GetStripSuffix())
	for _, t := range transforms {
		out = t.Re.ReplaceAllString(out, t.Replace)
	}
	return out
}

// ResolveBest picks the highest valid APK version out of a set of raw
// upstream version strings, after filtering and transforming each one.
func ResolveBest(ctx context.Context, versions []string, vh config.VersionHandler, patterns Patterns) (*Candidate, Stats, error) {
	log := clog.FromContext(ctx)
	var best *Candidate
	stats := Stats{Total: len(versions)}

	for _, upstream := range versions {
		if shouldSkip(ctx, upstream, vh, patterns.Ignore) {
			stats.Skipped++
			continue
		}

		transformed := applyTransforms(upstream, vh, patterns.Transforms)

		ver, err := apk.ParseVersion(transformed)
		if err != nil {
			stats.Skipped++
			if transformed != upstream {
				log.Debug("version skipped: APK parsing failed after transform — check your version-transform regex",
					"upstream", upstream, "transformed", transformed, "error", err)
			} else {
				log.Debug("version skipped: not a valid APK version", "upstream", upstream, "error", err)
			}
			continue
		}

		if best == nil || apk.CompareVersions(ver, best.apkVer) > 0 {
			best = &Candidate{Upstream: upstream, Transformed: transformed, apkVer: ver}
		}
	}

	if best == nil {
		return nil, stats, fmt.Errorf("all upstream tags were filtered out or could not be parsed as valid APK versions")
	}
	return best, stats, nil
}

// Compare returns apk.CompareVersions semantics for two raw version
// strings: negative if current < latest, zero if equal, positive if
// current > latest. An unparsable current version is treated as "always
// behind" and an unparsable latest version as "always ahead"
func Compare(ctx context.Context, currentStr, latestStr string) int {
	log := clog.FromContext(ctx)

	current, err := apk.ParseVersion(currentStr)
	if err != nil {
		log.Warn("failed to parse current version", "version", currentStr, "error", err)
		return -1
	}
	latest, err := apk.ParseVersion(latestStr)
	if err != nil {
		log.Warn("failed to parse resolved version", "version", latestStr, "error", err)
		return 1
	}
	return apk.CompareVersions(current, latest)
}
