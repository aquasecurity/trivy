package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/types"
)

// ConfigRun runs scan on config files
func ConfigRun(ctx *cli.Context) error {
	opt, err := initOption(ctx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// Disable OS and language analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{types.SecurityCheckConfig}

	// Skip downloading vulnerability DB
	opt.SkipDBUpdate = true

	// Run filesystem command internally
	return Run(ctx.Context, opt, filesystemStandaloneScanner, initCache)
}
