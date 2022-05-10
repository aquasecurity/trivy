package sarif

// Properties ...
type Properties map[string]interface{}

// PropertyBag ...
type PropertyBag struct {
	Properties Properties `json:"properties,omitempty"`
}

// NewPropertyBag creates a new PropertyBag and returns a pointer to it
func NewPropertyBag() *PropertyBag {
	return &PropertyBag{
		Properties: Properties{},
	}
}

// Add ...
func (propertyBag *PropertyBag) Add(key string, value interface{}) {
	propertyBag.Properties[key] = value
}

// AddString ...
func (propertyBag *PropertyBag) AddString(key, value string) {
	propertyBag.Add(key, value)
}

// AddBoolean ...
func (propertyBag *PropertyBag) AddBoolean(key string, value bool) {
	propertyBag.Add(key, value)
}

// AddInteger ...
func (propertyBag *PropertyBag) AddInteger(key string, value int) {
	propertyBag.Add(key, value)
}

// AttachPropertyBag adds a property bag to a rule
func (propertyBag *PropertyBag) AttachPropertyBag(pb *PropertyBag) {
	propertyBag.Properties = pb.Properties
}
