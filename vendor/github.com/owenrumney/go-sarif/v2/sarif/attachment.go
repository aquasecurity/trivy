package sarif

// Attachment ...
type Attachment struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Description      *Message          `json:"description,omitempty"`
	Rectangles       []*Rectangle      `json:"rectangles,omitempty"`
	PropertyBag
}

// NewAttachment creates a new Attachment and returns a pointer to it
func NewAttachment() *Attachment {
	return &Attachment{}
}

// WithArtifactionLocation sets the ArtifactionLocation
func (attachment *Attachment) WithArtifactionLocation(artifactLocation *ArtifactLocation) *Attachment {
	attachment.ArtifactLocation = artifactLocation
	return attachment
}

// WithDescription sets the Description
func (attachment *Attachment) WithDescription(description *Message) *Attachment {
	attachment.Description = description
	return attachment
}

// WithDescriptionText sets the DescriptionText
func (attachment *Attachment) WithDescriptionText(text string) *Attachment {
	if attachment.Description == nil {
		attachment.Description = &Message{}
	}
	attachment.Description.Text = &text
	return attachment
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (attachment *Attachment) WithDescriptionMarkdown(markdown string) *Attachment {
	if attachment.Description == nil {
		attachment.Description = &Message{}
	}
	attachment.Description.Markdown = &markdown
	return attachment
}

// WithRectangles sets the Rectangles
func (attachment *Attachment) WithRectangles(rectangles []*Rectangle) *Attachment {
	attachment.Rectangles = rectangles
	return attachment
}

// AddRectangle ...
func (attachment *Attachment) AddRectangle(rectangle *Rectangle) {
	attachment.Rectangles = append(attachment.Rectangles, rectangle)
}
