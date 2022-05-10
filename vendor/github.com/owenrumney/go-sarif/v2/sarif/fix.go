package sarif

// Fix ...
type Fix struct {
	Description     *Message          `json:"description,omitempty"`
	ArtifactChanges []*ArtifactChange `json:"artifactChanges"`
	PropertyBag
}

// NewFix creates a new Fix and returns a pointer to it
func NewFix() *Fix {
	return &Fix{}
}

// WithDescription sets the Description
func (fix *Fix) WithDescription(message *Message) *Fix {
	fix.Description = message
	return fix
}

// WithDescriptionText sets the DescriptionText
func (fix *Fix) WithDescriptionText(text string) *Fix {
	if fix.Description == nil {
		fix.Description = &Message{}
	}
	fix.Description.Text = &text
	return fix
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (fix *Fix) WithDescriptionMarkdown(markdown string) *Fix {
	if fix.Description == nil {
		fix.Description = &Message{}
	}
	fix.Description.Markdown = &markdown
	return fix
}

// WithArtifactChanges sets the ArtifactChanges
func (fix *Fix) WithArtifactChanges(artifactChanges []*ArtifactChange) *Fix {
	fix.ArtifactChanges = artifactChanges
	return fix
}

// AddArtifactChanges ...
func (fix *Fix) AddArtifactChanges(artifactChange *ArtifactChange) {
	fix.ArtifactChanges = append(fix.ArtifactChanges, artifactChange)
}
