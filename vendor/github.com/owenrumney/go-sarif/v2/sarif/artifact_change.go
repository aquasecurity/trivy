package sarif

// ArtifactChange ...
type ArtifactChange struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []*Replacement   `json:"replacements"`
	PropertyBag
}

// NewArtifactChange creates a new ArtifactChange and returns a pointer to it
func NewArtifactChange(artifactLocation *ArtifactLocation) *ArtifactChange {
	return &ArtifactChange{
		ArtifactLocation: *artifactLocation,
	}
}

// WithReplacement sets the Replacement
func (artifactChange *ArtifactChange) WithReplacement(replacement *Replacement) *ArtifactChange {
	artifactChange.Replacements = append(artifactChange.Replacements, replacement)
	return artifactChange
}
