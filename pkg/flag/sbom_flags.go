package flag

import (
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	ArtifactTypeFlag = Flag{
		Name:  "artifact-type",
		Value: "",
		Usage: "deprecated",
	}
	SBOMFormatFlag = Flag{
		Name:  "sbom-format",
		Value: "",
		Usage: "deprecated",
	}
)

type SBOMFlags struct {
	ArtifactType *Flag // deprecated
	SBOMFormat   *Flag // deprecated
}

type SBOMOptions struct {
	ArtifactType string // deprecated
	SBOMFormat   string // deprecated
}

func NewSBOMFlags() *SBOMFlags {
	return &SBOMFlags{
		ArtifactType: &ArtifactTypeFlag,
		SBOMFormat:   &SBOMFormatFlag,
	}
}

func (f *SBOMFlags) AddFlags(cmd *cobra.Command) {
	if f.ArtifactType != nil {
		cmd.Flags().String(ArtifactTypeFlag.Name, "", "deprecated")
		cmd.Flags().MarkHidden(ArtifactTypeFlag.Name) // nolint: gosec
	}
	if f.SBOMFormat != nil {
		cmd.Flags().String(SBOMFormatFlag.Name, "", "deprecated")
		cmd.Flags().MarkHidden(SBOMFormatFlag.Name) // nolint: gosec
	}
}

func (f *SBOMFlags) Bind(cmd *cobra.Command) error {
	// All the flags are deprecated
	return nil
}

func (f *SBOMFlags) ToOptions() (SBOMOptions, error) {
	artifactType := getString(f.ArtifactType)
	sbomFormat := getString(f.SBOMFormat)

	if artifactType != "" || sbomFormat != "" {
		log.Logger.Error("'trivy sbom' is now for scanning SBOM. " +
			"See https://github.com/aquasecurity/trivy/discussions/2407 for the detail")
		return SBOMOptions{}, xerrors.New("'--artifact-type' and '--sbom-format' are no longer available")
	}

	return SBOMOptions{}, nil
}
