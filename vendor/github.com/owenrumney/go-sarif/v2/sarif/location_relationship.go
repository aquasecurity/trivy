package sarif

// LocationRelationship ...
type LocationRelationship struct {
	Target      uint     `json:"target"`
	Kinds       []string `json:"kinds,omitempty"`
	Description *Message `json:"description,omitempty"`
	PropertyBag
}

// NewLocationRelationship creates a new LocationRelationship and returns a pointer to it
func NewLocationRelationship(target int) *LocationRelationship {
	t := uint(target)
	return &LocationRelationship{
		Target: t,
	}
}

// WithKinds sets the Kinds
func (locationRelationship *LocationRelationship) WithKinds(kinds []string) *LocationRelationship {
	locationRelationship.Kinds = kinds
	return locationRelationship
}

// AddKind ...
func (locationRelationship *LocationRelationship) AddKind(kind string) {
	locationRelationship.Kinds = append(locationRelationship.Kinds, kind)
}

// WithDescription sets the Description
func (locationRelationship *LocationRelationship) WithDescription(message *Message) *LocationRelationship {
	locationRelationship.Description = message
	return locationRelationship
}

// WithDescriptionText sets the DescriptionText
func (locationRelationship *LocationRelationship) WithDescriptionText(text string) *LocationRelationship {
	if locationRelationship.Description == nil {
		locationRelationship.Description = &Message{}
	}
	locationRelationship.Description.Text = &text
	return locationRelationship
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (locationRelationship *LocationRelationship) WithDescriptionMarkdown(markdown string) *LocationRelationship {
	if locationRelationship.Description == nil {
		locationRelationship.Description = &Message{}
	}
	locationRelationship.Description.Markdown = &markdown
	return locationRelationship
}
