package sarif

// Location ...
type Location struct {
	Id               *uint                   `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation       `json:"physicalLocation,omitempty"`
	LogicalLocations []*LogicalLocation      `json:"logicalLocations,omitempty"`
	Message          *Message                `json:"message,omitempty"`
	Annotations      []*Region               `json:"annotations,omitempty"`
	Relationships    []*LocationRelationship `json:"relationships,omitempty"`
	PropertyBag
}

// NewLocation creates a new Location and returns a pointer to it
func NewLocation() *Location {
	return &Location{}
}

// NewLocationWithPhysicalLocation creates a new LocationWithPhysicalLocation and returns a pointer to it
func NewLocationWithPhysicalLocation(physicalLocation *PhysicalLocation) *Location {
	return NewLocation().WithPhysicalLocation(physicalLocation)
}

// WithId sets the Id
func (location *Location) WithId(id int) *Location {
	i := uint(id)
	location.Id = &i
	return location
}

// WithPhysicalLocation sets the PhysicalLocation
func (location *Location) WithPhysicalLocation(physicalLocation *PhysicalLocation) *Location {
	location.PhysicalLocation = physicalLocation
	return location
}

// WithLogicalLocations sets the LogicalLocations
func (location *Location) WithLogicalLocations(logicalLocations []*LogicalLocation) *Location {
	location.LogicalLocations = logicalLocations
	return location
}

// AddLogicalLocations ...
func (location *Location) AddLogicalLocations(logicalLocation *LogicalLocation) {
	location.LogicalLocations = append(location.LogicalLocations, logicalLocation)
}

// WithMessage sets the Message
func (location *Location) WithMessage(message *Message) *Location {
	location.Message = message
	return location
}

// WithDescriptionText sets the DescriptionText
func (location *Location) WithDescriptionText(text string) *Location {
	if location.Message == nil {
		location.Message = &Message{}
	}
	location.Message.Text = &text
	return location
}

// WithDescriptionMarkdown sets the DescriptionMarkdown
func (location *Location) WithDescriptionMarkdown(markdown string) *Location {
	if location.Message == nil {
		location.Message = &Message{}
	}
	location.Message.Markdown = &markdown
	return location
}

// WithAnnotations sets the Annotations
func (location *Location) WithAnnotations(annotations []*Region) *Location {
	location.Annotations = annotations
	return location
}

// AddAnnotation ...
func (location *Location) AddAnnotation(annotation *Region) {
	location.Annotations = append(location.Annotations, annotation)
}

// WithRelationships sets the Relationships
func (location *Location) WithRelationships(locationRelationships []*LocationRelationship) *Location {
	location.Relationships = locationRelationships
	return location
}

// AddRelationship ...
func (location *Location) AddRelationship(locationRelationship *LocationRelationship) {
	location.Relationships = append(location.Relationships, locationRelationship)
}
