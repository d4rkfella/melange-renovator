package discover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/d4rkfella/melange-renovator/internal/app"
	"gopkg.in/yaml.v3"
)

// renovatorConfigFileNames lists the file names checked, in order, at a
// repository's root. The first one found wins — mirrors upstream
// Renovate's configFileNames behavior, just with our own filename so it
// never collides with an actual renovate.json a repo might also have.
var renovatorConfigFileNames = []string{
	".melange-renovator.yml",
	".melange-renovator.yaml",
}

// RenovatorConfigLoader implements app.RenovatorConfigLoader by reading a small YAML
// file from the repository root.
type RenovatorConfigLoader struct{}

type renovatorConfigFile struct {
	DependencyDashboardTitle *string  `yaml:"dependencyDashboardTitle"`
	RebaseWhen               *string  `yaml:"rebaseWhen"`
	RecreateWhen             *string  `yaml:"recreateWhen"`
	ConfigFilePatterns       []string `yaml:"configFilePatterns"`
	IgnorePaths              []string `yaml:"ignorePaths"`
}

func (RenovatorConfigLoader) Load(ctx context.Context, root string) (app.RenovatorConfig, error) {
	for _, name := range renovatorConfigFileNames {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return app.RenovatorConfig{}, fmt.Errorf("reading %s: %w", name, err)
		}

		var raw renovatorConfigFile
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return app.RenovatorConfig{}, fmt.Errorf("parsing %s: %w", name, err)
		}

		cfg := app.RenovatorConfig{
			ConfigFilePatterns: raw.ConfigFilePatterns,
			DashboardTitle:     raw.DependencyDashboardTitle,
			IgnorePaths:        raw.IgnorePaths,
		}
		if raw.RebaseWhen != nil {
			p := app.RebasePolicy(*raw.RebaseWhen)
			if !p.Valid() {
				return app.RenovatorConfig{}, fmt.Errorf("%s: invalid rebaseWhen %q", name, *raw.RebaseWhen)
			}
			cfg.RebaseWhen = &p
		}
		if raw.RecreateWhen != nil {
			p := app.RecreatePolicy(*raw.RecreateWhen)
			if !p.Valid() {
				return app.RenovatorConfig{}, fmt.Errorf("%s: invalid recreateWhen %q", name, *raw.RecreateWhen)
			}
			cfg.RecreateWhen = &p
		}
		return cfg, nil
	}
	return app.RenovatorConfig{}, nil
}
