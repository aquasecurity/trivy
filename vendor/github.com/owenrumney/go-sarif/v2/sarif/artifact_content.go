package sarif

// ArtifactContent ...
type ArtifactContent struct { 
	Text     *string                   `json:"text,omitempty"`
	Binary   *string                   `json:"binary,omitempty"`
	Rendered *MultiformatMessageString `json:"rendered,omitempty"`
	PropertyBag
}

// NewArtifactContent creates a new ArtifactContent and returns a pointer to it
func NewArtifactContent() *ArtifactContent {
	return &ArtifactContent{}
}

// WithText sets the Text
func (artifactContent *ArtifactContent) WithText(text string) *ArtifactContent {
	artifactContent.Text = &text
	return artifactContent
}

// WithBinary sets the Binary
func (artifactContent *ArtifactContent) WithBinary(binary string) *ArtifactContent {
	artifactContent.Binary = &binary
	return artifactContent
}

// WithRendered sets the Rendered
func (artifactContent *ArtifactContent) WithRendered(mms *MultiformatMessageString) *ArtifactContent {
	artifactContent.Rendered = mms
	return artifactContent
}
