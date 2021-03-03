package artifact

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/pkg/types"
)

// IaCRun runs scan on IaC config files
func IaCRun(cliCtx *cli.Context) error {
	c, err := config.New(cliCtx)
	if err != nil {
		return err
	}

	// initialize config
	if err = c.Init(); err != nil {
		return xerrors.Errorf("failed to initialize options: %w", err)
	}

	// Scan only IaC config files
	c.VulnType = nil
	c.SecurityChecks = []string{types.SecurityCheckIaC}

	// Run filesystem command internally
	return run(c, filesystemScanner)
}
