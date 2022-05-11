package sarif

// Region ...
type Region struct {
	StartLine      *int             `json:"startLine,omitempty"`
	StartColumn    *int             `json:"startColumn,omitempty"`
	EndLine        *int             `json:"endLine,omitempty"`
	EndColumn      *int             `json:"endColumn,omitempty"`
	CharOffset     *int             `json:"charOffset,omitempty"`
	CharLength     *int             `json:"charLength,omitempty"`
	ByteOffset     *int             `json:"byteOffset,omitempty"`
	ByteLength     *int             `json:"byteLength,omitempty"`
	Snippet        *ArtifactContent `json:"snippet,omitempty"`
	Message        *Message         `json:"message,omitempty"`
	SourceLanguage *string          `json:"sourceLanguage,omitempty"`
	PropertyBag
}

// NewRegion creates a new Region and returns a pointer to it
func NewRegion() *Region {
	return &Region{}
}

// NewSimpleRegion creates a new SimpleRegion and returns a pointer to it
func NewSimpleRegion(startLine, endLine int) *Region {
	return NewRegion().
		WithStartLine(startLine).
		WithEndLine(endLine)
}

// WithStartLine sets the StartLine
func (region *Region) WithStartLine(startLine int) *Region {
	region.StartLine = &startLine
	return region
}

// WithStartColumn sets the StartColumn
func (region *Region) WithStartColumn(startColumn int) *Region {
	region.StartColumn = &startColumn
	return region
}

// WithEndLine sets the EndLine
func (region *Region) WithEndLine(endLine int) *Region {
	region.EndLine = &endLine
	return region
}

// WithEndColumn sets the EndColumn
func (region *Region) WithEndColumn(endColumn int) *Region {
	region.EndColumn = &endColumn
	return region
}

// WithCharOffset sets the CharOffset
func (region *Region) WithCharOffset(charOffset int) *Region {
	region.CharOffset = &charOffset
	return region
}

// WithCharLength sets the CharLength
func (region *Region) WithCharLength(charLength int) *Region {
	region.CharLength = &charLength
	return region
}

// WithByteOffset sets the ByteOffset
func (region *Region) WithByteOffset(byteOffset int) *Region {
	region.ByteOffset = &byteOffset
	return region
}

// WithByteLength sets the ByteLength
func (region *Region) WithByteLength(byteLength int) *Region {
	region.ByteLength = &byteLength
	return region
}

// WithSnippet sets the Snippet
func (region *Region) WithSnippet(snippet *ArtifactContent) *Region {
	region.Snippet = snippet
	return region
}

// WithMessage sets the Message
func (region *Region) WithMessage(message *Message) *Region {
	region.Message = message
	return region
}

// WithTextMessage sets the Message text
func (region *Region) WithTextMessage(text string) *Region {
	if region.Message == nil {
		region.Message = &Message{}
	}
	region.Message.Text = &text
	return region
}

// WithMessageMarkdown sets the Message markdown
func (region *Region) WithMessageMarkdown(markdown string) *Region {
	if region.Message == nil {
		region.Message = &Message{}
	}
	region.Message.Markdown = &markdown
	return region
}

// WithSourceLanguage sets the SourceLanguage
func (region *Region) WithSourceLanguage(sourceLanguage string) *Region {

	return region
}
