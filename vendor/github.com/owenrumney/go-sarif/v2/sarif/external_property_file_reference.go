package sarif

// ExternalPropertyFileReference ...
type ExternalPropertyFileReference struct {
	GUID      *string           `json:"guid,omitempty"`
	ItemCount *int              `json:"itemCount,omitempty"`
	Location  *ArtifactLocation `json:"location,omitempty"`
	PropertyBag

}

// NewExternalPropertyFileReference creates a new ExternalPropertyFileReference and returns a pointer to it
func NewExternalPropertyFileReference() *ExternalPropertyFileReference {
	return &ExternalPropertyFileReference{}
}

// WithGUID sets the GUID
func (externalPropertyFileReferences *ExternalPropertyFileReference) WithGUID(guid string) *ExternalPropertyFileReference {
	externalPropertyFileReferences.GUID = &guid
	return externalPropertyFileReferences
}

// WithItemCount sets the ItemCount
func (externalPropertyFileReferences *ExternalPropertyFileReference) WithItemCount(itemCount int) *ExternalPropertyFileReference {
	externalPropertyFileReferences.ItemCount = &itemCount
	return externalPropertyFileReferences
}
