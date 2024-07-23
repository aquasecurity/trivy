package flag

var (
	ArtifactTypeFlag = Flag[string]{
		Name:       "artifact-type",
		ConfigName: "sbom.artifact-type",
		Usage:      "deprecated",
		Removed:    `Use 'trivy image' or other subcommands. See also https://github.com/aquasecurity/trivy/discussions/2407`,
	}
	SBOMFormatFlag = Flag[string]{
		Name:       "sbom-format",
		ConfigName: "sbom.format",
		Usage:      "deprecated",
		Removed:    `Use 'trivy image' or other subcommands. See also https://github.com/aquasecurity/trivy/discussions/2407`,
	}
)

type SBOMFlagGroup struct {
	ArtifactType *Flag[string] // deprecated
	SBOMFormat   *Flag[string] // deprecated
}

type SBOMOptions struct{}

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

	return SBOMOptions{}, nil
}
