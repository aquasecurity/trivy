package sarif

// Suppression ...
type Suppression struct {
	Kind          string    `json:"kind"`
	Status        *string   `json:"status"`
	Location      *Location `json:"location"`
	Guid          *string   `json:"guid"`
	Justification *string   `json:"justification"`
	PropertyBag

}

// NewSuppression creates a new Suppression and returns a pointer to it
func NewSuppression(kind string) *Suppression {
	return &Suppression{
		Kind: kind,
	}
}

// WithStatus sets the Status
func (s *Suppression) WithStatus(status string) *Suppression {
	s.Status = &status
	return s
}

// WithLocation sets the Location
func (s *Suppression) WithLocation(location *Location) *Suppression {
	s.Location = location
	return s
}

// WithGuid sets the Guid
func (s *Suppression) WithGuid(guid string) *Suppression {
	s.Guid = &guid
	return s
}

// WithJustifcation sets the Justifcation
func (s *Suppression) WithJustifcation(justification string) *Suppression {
	s.Justification = &justification
	return s
}
