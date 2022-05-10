package sarif

// PhysicalLocation ...
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
	Address          *Address          `json:"address,omitempty"`
	PropertyBag
}

// NewPhysicalLocation creates a new PhysicalLocation and returns a pointer to it
func NewPhysicalLocation() *PhysicalLocation {
	return &PhysicalLocation{}
}

// WithArtifactLocation sets the ArtifactLocation
func (pl *PhysicalLocation) WithArtifactLocation(artifactLocation *ArtifactLocation) *PhysicalLocation {
	pl.ArtifactLocation = artifactLocation
	return pl
}

// WithRegion sets the Region
func (pl *PhysicalLocation) WithRegion(region *Region) *PhysicalLocation {
	pl.Region = region
	return pl
}

// WithContextRegion sets the ContextRegion
func (pl *PhysicalLocation) WithContextRegion(contextRegion *Region) *PhysicalLocation {
	pl.ContextRegion = contextRegion
	return pl
}

// WithAddress sets the Address
func (pl *PhysicalLocation) WithAddress(address *Address) *PhysicalLocation {
	pl.Address = address
	return pl
}
