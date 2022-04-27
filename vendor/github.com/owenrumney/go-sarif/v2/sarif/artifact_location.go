package sarif

// ArtifactLocation ...
type ArtifactLocation struct {
	URI         *string  `json:"uri,omitempty"`
	URIBaseId   *string  `json:"uriBaseId,omitempty"`
	Index       *uint    `json:"index,omitempty"`
	Description *Message `json:"description,omitempty"`
	PropertyBag
}

// NewArtifactLocation creates a new ArtifactLocation and returns a pointer to it
func NewArtifactLocation() *ArtifactLocation {
	return &ArtifactLocation{}
}

// NewSimpleArtifactLocation creates a new SimpleArtifactLocation and returns a pointer to it
func NewSimpleArtifactLocation(uri string) *ArtifactLocation {
	return NewArtifactLocation().WithUri(uri)
}

// WithUri sets the Uri
func (artifactLocation *ArtifactLocation) WithUri(uri string) *ArtifactLocation {
	artifactLocation.URI = &uri
	return artifactLocation
}

// WithUriBaseId sets the UriBaseId
func (artifactLocation *ArtifactLocation) WithUriBaseId(uriBaseId string) *ArtifactLocation {
	artifactLocation.URIBaseId = &uriBaseId
	return artifactLocation
}

// WithIndex sets the Index
func (artifactLocation *ArtifactLocation) WithIndex(index int) *ArtifactLocation {
	i := uint(index)
	artifactLocation.Index = &i
	return artifactLocation
}

// WithDescription sets the Description
func (artifactLocation *ArtifactLocation) WithDescription(message *Message) *ArtifactLocation {
	artifactLocation.Description = message
	return artifactLocation
}

// WithDescriptionText sets the DescriptionText
func (artifactLocation *ArtifactLocation) WithDescriptionText(text string) *ArtifactLocation {
	if artifactLocation.Description == nil {
		artifactLocation.Description = &Message{}
	}
	artifactLocation.Description.Text = &text
	return artifactLocation
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (artifactLocation *ArtifactLocation) WithDescriptionMarkdown(markdown string) *ArtifactLocation {
	if artifactLocation.Description == nil {
		artifactLocation.Description = &Message{}
	}
	artifactLocation.Description.Markdown = &markdown
	return artifactLocation
}
