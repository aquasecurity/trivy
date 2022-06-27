package option

import (
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var supportedSbomFormats = []string{report.FormatCycloneDX, report.FormatSPDX, report.FormatSPDXJSON,
	report.FormatGitHub}

// SbomOption holds the options for SBOM generation
type SbomOption struct {
	ArtifactType string // deprecated
	SbomFormat   string // deprecated
}

// NewSbomOption is the factory method to return SBOM options
func NewSbomOption(c *cli.Context) SbomOption {
	return SbomOption{
		ArtifactType: c.String("artifact-type"),
		SbomFormat:   c.String("sbom-format"),
	}
}

// Init initialize the CLI context for SBOM generation
func (c *SbomOption) Init(ctx *cli.Context, logger *zap.SugaredLogger) error {
	if ctx.Command.Name != "sbom" {
		return nil
	}

	if c.ArtifactType != "" || c.SbomFormat != "" {
		logger.Error("'trivy sbom' is now for scanning SBOM. " +
			"See https://github.com/aquasecurity/trivy/discussions/2407 for the detail")
	}

	return nil
}
