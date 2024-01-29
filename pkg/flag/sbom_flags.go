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
)

type SBOMFlagGroup struct {
	ArtifactType *Flag[string] // deprecated
	SBOMFormat   *Flag[string] // deprecated
}

type SBOMOptions struct {
}

func NewSBOMFlagGroup() *SBOMFlagGroup {
	return &SBOMFlagGroup{
		ArtifactType: ArtifactTypeFlag.Clone(),
		SBOMFormat:   SBOMFormatFlag.Clone(),
	}
}

func (f *SBOMFlagGroup) Name() string {
	return "SBOM"
}

func (f *SBOMFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ArtifactType,
		f.SBOMFormat,
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

	return SBOMOptions{}, nil
}
