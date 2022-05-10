package sarif

// Replacement ...
type Replacement struct {
	DeletedRegion   Region           `json:"deletedRegion"`
	InsertedContent *ArtifactContent `json:"insertedContent,omitempty"`
	PropertyBag

}

// NewReplacement creates a new Replacement and returns a pointer to it
func NewReplacement(region *Region) *Replacement {
	return &Replacement{
		DeletedRegion: *region,
	}
}

// WithInsertedContent sets the InsertedContent
func (r *Replacement) WithInsertedContent(artifactContent *ArtifactContent) *Replacement {
	r.InsertedContent = artifactContent
	return r
}
