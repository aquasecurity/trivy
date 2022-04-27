package option

import (
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var supportedSbomFormats = []string{"cyclonedx", "spdx", "spdx-json"}

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
