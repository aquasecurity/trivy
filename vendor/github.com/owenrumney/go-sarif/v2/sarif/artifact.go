package sarif

// Artifact ...
type Artifact struct {

	Location            *ArtifactLocation `json:"location,omitempty"`
	ParentIndex         *uint             `json:"parentIndex,omitempty"`
	Offset              *uint             `json:"offset,omitempty"`
	Length              int               `json:"length"`
	Roles               []string          `json:"roles,omitempty"`
	MimeType            *string           `json:"mimeType,omitempty"`
	Contents            *ArtifactContent  `json:"contents,omitempty"`
	Encoding            *string           `json:"encoding,omitempty"`
	SourceLanguage      *string           `json:"sourceLanguage,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	LastModifiedTimeUtc *string           `json:"lastModifiedTimeUtc,omitempty"`
	Description         *Message          `json:"description,omitempty"`
	PropertyBag
}

// NewArtifact creates a new Artifact and returns a pointer to it
func NewArtifact() *Artifact {
	return &Artifact{}
}

// WithLocation sets the Location
func (artifact *Artifact) WithLocation(artifactLocation *ArtifactLocation) *Artifact {
	artifact.Location = artifactLocation
	return artifact
}

// WithParentIndex sets the ParentIndex
func (artifact *Artifact) WithParentIndex(parentIndex int) *Artifact {
	i := uint(parentIndex)
	artifact.ParentIndex = &i
	return artifact
}

// WithOffset sets the Offset
func (artifact *Artifact) WithOffset(offset int) *Artifact {
	o := uint(offset)
	artifact.Offset = &o
	return artifact
}

// WithLength sets the Length
func (artifact *Artifact) WithLength(length int) *Artifact {
	artifact.Length = length
	return artifact
}

// WithRole sets the Role
func (artifact *Artifact) WithRole(role string) *Artifact {
	artifact.Roles = append(artifact.Roles, role)
	return artifact
}

// WithMimeType sets the MimeType
func (artifact *Artifact) WithMimeType(mimeType string) *Artifact {
	artifact.MimeType = &mimeType
	return artifact
}

// WithContents sets the Contents
func (artifact *Artifact) WithContents(artifactContent *ArtifactContent) *Artifact {
	artifact.Contents = artifactContent
	return artifact
}

// WithEncoding sets the Encoding
func (artifact *Artifact) WithEncoding(encoding string) *Artifact {
	artifact.Encoding = &encoding
	return artifact
}

// WithSourceLanguage sets the SourceLanguage
func (artifact *Artifact) WithSourceLanguage(sourceLanguage string) *Artifact {
	artifact.SourceLanguage = &sourceLanguage
	return artifact
}

// WithHashes sets the Hashes
func (artifact *Artifact) WithHashes(hashes map[string]string) *Artifact {
	artifact.Hashes = hashes
	return artifact
}

// WithLastModifiedTimeUtc sets the LastModifiedTimeUtc
func (artifact *Artifact) WithLastModifiedTimeUtc(lastModified string) *Artifact {
	artifact.LastModifiedTimeUtc = &lastModified
	return artifact
}

// WithDescription sets the Description
func (artifact *Artifact) WithDescription(message *Message) *Artifact {
	artifact.Description = message
	return artifact
}

// WithDescriptionText sets the DescriptionText
func (artifact *Artifact) WithDescriptionText(text string) *Artifact {
	if artifact.Description == nil {
		artifact.Description = &Message{}
	}
	artifact.Description.Text = &text
	return artifact
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (artifact *Artifact) WithDescriptionMarkdown(markdown string) *Artifact {
	if artifact.Description == nil {
		artifact.Description = &Message{}
	}
	artifact.Description.Markdown = &markdown
	return artifact
}
