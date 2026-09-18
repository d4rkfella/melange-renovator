package versioning

import (
	"fmt"

	"chainguard.dev/melange/pkg/config"
	"github.com/d4rkfella/melange-renovator/internal/report"
)

func toTransformInfo(ts []config.VersionTransform) []report.VersionTransform {
	out := make([]report.VersionTransform, 0, len(ts))
	for _, t := range ts {
		out = append(out, report.VersionTransform{Match: t.Match, Replace: t.Replace})
	}
	return out
}

// BuildMonitorReport describes a package's configured update monitor in
// the shape reported in the tool's JSON output, regardless of whether a
// Resolver could actually be constructed for it — a config with no
// monitor still gets a monitor.type of "none" in the report.
func BuildMonitorReport(cfg *config.Configuration) report.Monitor {
	common := func(vh config.VersionHandler) report.Monitor {
		return report.Monitor{
			FilterPrefix:        vh.GetFilterPrefix(),
			FilterContains:      vh.GetFilterContains(),
			StripPrefix:         vh.GetStripPrefix(),
			StripSuffix:         vh.GetStripSuffix(),
			VersionTransforms:   toTransformInfo(cfg.Update.VersionTransform),
			IgnoreRegexPatterns: cfg.Update.IgnoreRegexPatterns,
		}
	}

	switch {
	case cfg.Update.GitHubMonitor != nil:
		gh := cfg.Update.GitHubMonitor
		m := common(gh)
		m.Type = "github-releases"
		if gh.UseTags {
			m.Type = "github-tags"
		}
		m.Identifier = gh.Identifier
		m.UseTags = gh.UseTags
		m.EnablePreReleaseTags = cfg.Update.EnablePreReleaseTags
		return m

	case cfg.Update.GitMonitor != nil:
		m := common(cfg.Update.GitMonitor)
		m.Type = "git-refs"
		m.Identifier = GitCheckoutRepoURL(cfg)
		return m

	case cfg.Update.ReleaseMonitor != nil:
		rm := cfg.Update.ReleaseMonitor
		m := common(rm)
		m.Type = "release-monitor"
		m.Identifier = fmt.Sprintf("%d", rm.Identifier)
		m.EnablePreReleaseTags = cfg.Update.EnablePreReleaseTags
		return m

	case cfg.Update.OCIMonitor != nil:
		oci := cfg.Update.OCIMonitor
		m := common(oci)
		m.Type = "oci"
		m.Identifier = oci.Identifier
		return m
	}

	return report.Monitor{Type: "none"}
}
