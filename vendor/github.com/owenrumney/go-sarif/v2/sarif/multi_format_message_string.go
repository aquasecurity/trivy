package sarif

// MultiformatMessageString ...
type MultiformatMessageString struct {
	Text     *string `json:"text,omitempty"`
	Markdown *string `json:"markdown,omitempty"`
	PropertyBag
}

// NewMarkdownMultiformatMessageString creates a new MarkdownMultiformatMessageString and returns a pointer to it
func NewMarkdownMultiformatMessageString(markdown string) *MultiformatMessageString {
	return &MultiformatMessageString{
		Markdown: &markdown,
	}
}

// NewMultiformatMessageString creates a new MultiformatMessageString and returns a pointer to it
func NewMultiformatMessageString(text string) *MultiformatMessageString {
	return &MultiformatMessageString{
		Text: &text,
	}
}

// WithText sets the Text
func (multiFormatMessageString *MultiformatMessageString) WithText(text string) *MultiformatMessageString {
	multiFormatMessageString.Text = &text
	return multiFormatMessageString
}

// WithMarkdown sets the Markdown
func (multiFormatMessageString *MultiformatMessageString) WithMarkdown(markdown string) *MultiformatMessageString {
	multiFormatMessageString.Markdown = &markdown
	return multiFormatMessageString
}
