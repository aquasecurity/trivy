package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

// ConfigRun runs scan on config files
func ConfigRun(cliCtx *cli.Context) error {
	opt, err := NewOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	// initialize config
	if err = opt.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// Scan only config files
	opt.VulnType = nil
	opt.SecurityChecks = []string{types.SecurityCheckConfig}

	// Run filesystem command internally
	return Run(opt, filesystemScanner)
}
