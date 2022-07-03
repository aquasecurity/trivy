package flag

import (
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

const (
	ArtifactTypeFlag = "artifact-type"
	SBOMFormat       = "sbom-format"
)

type SBOMFlags struct {
	ArtifactType *string // deprecated
	SBOMFormat   *string // deprecated
}

type SBOMOptions struct {
	ArtifactType string // deprecated
	SBOMFormat   string // deprecated
}

func NewDefaultSBOMFlags() *SBOMFlags {
	return &SBOMFlags{
		ArtifactType: lo.ToPtr(""),
		SBOMFormat:   lo.ToPtr(""),
	}
}

func (f *SBOMFlags) AddFlags(cmd *cobra.Command) {
	if f.ArtifactType != nil {
		cmd.Flags().String(ArtifactTypeFlag, *f.ArtifactType, "deprecated")
		cmd.Flags().MarkHidden(ArtifactTypeFlag)
	}
	if f.SBOMFormat != nil {
		cmd.Flags().String(SBOMFormat, *f.SBOMFormat, "deprecated")
		cmd.Flags().MarkHidden(SBOMFormat)
	}
}

func (f *SBOMFlags) ToOptions() (SBOMOptions, error) {
	artifactType := viper.GetString(ArtifactTypeFlag)
	sbomFormat := viper.GetString(SBOMFormat)

	if artifactType != "" || sbomFormat != "" {
		log.Logger.Error("'trivy sbom' is now for scanning SBOM. " +
			"See https://github.com/aquasecurity/trivy/discussions/2407 for the detail")
		return SBOMOptions{}, xerrors.New("'--artifact-type' and '--sbom-format' are no longer available")
	}

	return SBOMOptions{}, nil
}
