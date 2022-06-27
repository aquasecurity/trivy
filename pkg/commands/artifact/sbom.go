package artifact

import (
	"github.com/urfave/cli/v2"
)

// SBOMRun scans SBOM for vulnerabilities
func SBOMRun(ctx *cli.Context) error {
	return Run(ctx, sbomArtifact)
}
