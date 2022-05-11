package sarif

// TranslationMetadata ...
type TranslationMetadata struct {
	DownloadURI      *string                   `json:"downloadUri,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	FullName         *string                   `json:"fullName,omitempty"`
	InformationURI   *string                   `json:"informationUri,omitempty"`
	Name             *string                   `json:"name"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	PropertyBag
}

// NewTranslationMetadata creates a new TranslationMetadata and returns a pointer to it
func NewTranslationMetadata() *TranslationMetadata {
	return &TranslationMetadata{}
}

// WithDownloadURI sets the DownloadURI
func (translationMetadata *TranslationMetadata) WithDownloadURI(downloadURI string) *TranslationMetadata {
	translationMetadata.DownloadURI = &downloadURI
	return translationMetadata
}

// WithFullDescription sets the FullDescription
func (translationMetadata *TranslationMetadata) WithFullDescription(message *MultiformatMessageString) *TranslationMetadata {
	translationMetadata.FullDescription = message
	return translationMetadata
}

// WithFullDescriptionText sets the FullDescriptionText
func (translationMetadata *TranslationMetadata) WithFullDescriptionText(text string) *TranslationMetadata {
	if translationMetadata.FullDescription == nil {
		translationMetadata.FullDescription = &MultiformatMessageString{}
	}
	translationMetadata.FullDescription.Text = &text
	return translationMetadata
}

// WithFullDescriptionMarkdown sets the FullDescriptionMarkdown
func (translationMetadata *TranslationMetadata) WithFullDescriptionMarkdown(markdown string) *TranslationMetadata {
	if translationMetadata.FullDescription == nil {
		translationMetadata.FullDescription = &MultiformatMessageString{}
	}
	translationMetadata.FullDescription.Markdown = &markdown
	return translationMetadata
}

// WithFullName sets the FullName
func (translationMetadata *TranslationMetadata) WithFullName(fullname string) *TranslationMetadata {
	translationMetadata.FullName = &fullname
	return translationMetadata
}

// WithInformationURI sets the InformationURI
func (translationMetadata *TranslationMetadata) WithInformationURI(informationURI string) *TranslationMetadata {
	translationMetadata.InformationURI = &informationURI
	return translationMetadata
}

// WithName sets the Name
func (translationMetadata *TranslationMetadata) WithName(name string) *TranslationMetadata {
	translationMetadata.Name = &name

	return translationMetadata
}

// WithShortDescription sets the ShortDescription
func (translationMetadata *TranslationMetadata) WithShortDescription(message *MultiformatMessageString) *TranslationMetadata {
	translationMetadata.ShortDescription = message
	return translationMetadata
}

// WithShortShortDescriptionText sets the ShortShortDescriptionText
func (translationMetadata *TranslationMetadata) WithShortShortDescriptionText(text string) *TranslationMetadata {
	if translationMetadata.ShortDescription == nil {
		translationMetadata.ShortDescription = &MultiformatMessageString{}
	}
	translationMetadata.ShortDescription.Text = &text
	return translationMetadata
}

// WithShortDescriptionMarkdown sets the ShortDescriptionMarkdown
func (translationMetadata *TranslationMetadata) WithShortDescriptionMarkdown(markdown string) *TranslationMetadata {
	if translationMetadata.ShortDescription == nil {
		translationMetadata.ShortDescription = &MultiformatMessageString{}
	}
	translationMetadata.ShortDescription.Markdown = &markdown
	return translationMetadata
}
