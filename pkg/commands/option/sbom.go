package option

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/report"
)

var supportedSbomFormats = []string{report.FormatCycloneDX, report.FormatSPDX, report.FormatSPDXJSON, report.FormatGitHub}

// SbomOption holds the options for SBOM generation
type SbomOption struct {
	ArtifactType string
	SbomFormat   string
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

	if !slices.Contains(supportedSbomFormats, c.SbomFormat) {
		logger.Errorf(`"--format" must be %q`, supportedSbomFormats)
		return xerrors.Errorf(`"--format" must be %q`, supportedSbomFormats)
	}

	return nil
}
