package sarif

// Rectangle ...
type Rectangle struct {
	Bottom  *float64 `json:"bottom,omitempty"`
	Left    *float64 `json:"left,omitempty"`
	Right   *float64 `json:"right,omitempty"`
	Top     *float64 `json:"top,omitempty"`
	Message *Message `json:"message,omitempty"`
	PropertyBag

}

// NewRectangle creates a new Rectangle and returns a pointer to it
func NewRectangle() *Rectangle {
	return &Rectangle{}
}

// WithBottom sets the Bottom
func (rectangle *Rectangle) WithBottom(bottom float64) *Rectangle {
	rectangle.Bottom = &bottom
	return rectangle
}

// WithTop sets the Top
func (rectangle *Rectangle) WithTop(top float64) *Rectangle {
	rectangle.Top = &top
	return rectangle
}

// WithLeft sets the Left
func (rectangle *Rectangle) WithLeft(withLeft float64) *Rectangle {
	rectangle.Left = &withLeft
	return rectangle
}

// WithRight sets the Right
func (rectangle *Rectangle) WithRight(right float64) *Rectangle {
	rectangle.Right = &right
	return rectangle
}

// WithMessage sets the Message
func (rectangle *Rectangle) WithMessage(message *Message) *Rectangle {
	rectangle.Message = message
	return rectangle
}

// WithTextMessage sets the Message text
func (rectangle *Rectangle) WithTextMessage(text string) *Rectangle {
	if rectangle.Message == nil {
		rectangle.Message = &Message{}
	}
	rectangle.Message.Text = &text
	return rectangle
}

// WithMessageMarkdown sets the Message markdown
func (rectangle *Rectangle) WithMessageMarkdown(markdown string) *Rectangle {
	if rectangle.Message == nil {
		rectangle.Message = &Message{}
	}
	rectangle.Message.Markdown = &markdown
	return rectangle
}
