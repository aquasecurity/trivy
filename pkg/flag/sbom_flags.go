package flag

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	ArtifactTypeFlag = Flag[string]{
		Name:       "artifact-type",
		ConfigName: "sbom.artifact-type",
		Usage:      "deprecated",
		Deprecated: true,
	}
	SBOMFormatFlag = Flag[string]{
		Name:       "sbom-format",
		ConfigName: "sbom.format",
		Usage:      "deprecated",
		Deprecated: true,
	}
	VEXFlag = Flag[string]{
		Name:       "vex",
		ConfigName: "sbom.vex",
		Default:    "",
		Usage:      "[EXPERIMENTAL] file path to VEX",
	}
)

type SBOMFlagGroup struct {
	ArtifactType *Flag[string] // deprecated
	SBOMFormat   *Flag[string] // deprecated
	VEXPath      *Flag[string]
}

type SBOMOptions struct {
	VEXPath string
}

func NewSBOMFlagGroup() *SBOMFlagGroup {
	return &SBOMFlagGroup{
		ArtifactType: ArtifactTypeFlag.Clone(),
		SBOMFormat:   SBOMFormatFlag.Clone(),
		VEXPath:      VEXFlag.Clone(),
	}
}

func (f *SBOMFlagGroup) Name() string {
	return "SBOM"
}

func (f *SBOMFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ArtifactType,
		f.SBOMFormat,
		f.VEXPath,
	}
}

func (f *SBOMFlagGroup) ToOptions() (SBOMOptions, error) {
	if err := parseFlags(f); err != nil {
		return SBOMOptions{}, err
	}

	artifactType := f.ArtifactType.Value()
	sbomFormat := f.SBOMFormat.Value()

	if artifactType != "" || sbomFormat != "" {
		log.Logger.Error("'trivy sbom' is now for scanning SBOM. " +
			"See https://github.com/aquasecurity/trivy/discussions/2407 for the detail")
		return SBOMOptions{}, xerrors.New("'--artifact-type' and '--sbom-format' are no longer available")
	}

	return SBOMOptions{
		VEXPath: f.VEXPath.Value(),
	}, nil
}
