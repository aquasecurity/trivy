package flag

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	ArtifactTypeFlag = Flag{
		Name:       "artifact-type",
		ConfigName: "sbom.artifact-type",
		Default:    "",
		Usage:      "deprecated",
		Deprecated: true,
	}
	SBOMFormatFlag = Flag{
		Name:       "sbom-format",
		ConfigName: "sbom.format",
		Default:    "",
		Usage:      "deprecated",
		Deprecated: true,
	}
	VEXFlag = Flag{
		Name:       "vex",
		ConfigName: "sbom.vex",
		Default:    "",
		Usage:      "[EXPERIMENTAL] file path to VEX",
	}
)

type SBOMFlagGroup struct {
	ArtifactType *Flag // deprecated
	SBOMFormat   *Flag // deprecated
	VEXPath      *Flag
}

type SBOMOptions struct {
	VEXPath string
}

func NewSBOMFlagGroup() *SBOMFlagGroup {
	return &SBOMFlagGroup{
		ArtifactType: &ArtifactTypeFlag,
		SBOMFormat:   &SBOMFormatFlag,
		VEXPath:      &VEXFlag,
	}
}

func (f *SBOMFlagGroup) Name() string {
	return "SBOM"
}

func (f *SBOMFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.ArtifactType,
		f.SBOMFormat,
		f.VEXPath,
	}
}

func (f *SBOMFlagGroup) ToOptions() (SBOMOptions, error) {
	artifactType := getString(f.ArtifactType)
	sbomFormat := getString(f.SBOMFormat)

	if artifactType != "" || sbomFormat != "" {
		log.Logger.Error("'trivy sbom' is now for scanning SBOM. " +
			"See https://github.com/aquasecurity/trivy/discussions/2407 for the detail")
		return SBOMOptions{}, xerrors.New("'--artifact-type' and '--sbom-format' are no longer available")
	}

	return SBOMOptions{
		VEXPath: getString(f.VEXPath),
	}, nil
}
