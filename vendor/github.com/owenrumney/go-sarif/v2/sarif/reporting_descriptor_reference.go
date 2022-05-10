package sarif

// ReportingDescriptorReference ...
type ReportingDescriptorReference struct {
	PropertyBag
	Id            *string                 `json:"id,omitempty"`
	Index         *uint                   `json:"index,omitempty"`
	Guid          *string                 `json:"guid,omitempty"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

// NewReportingDescriptorReference creates a new ReportingDescriptorReference and returns a pointer to it
func NewReportingDescriptorReference() *ReportingDescriptorReference {
	return &ReportingDescriptorReference{}
}

// WithId sets the Id
func (r *ReportingDescriptorReference) WithId(id string) *ReportingDescriptorReference {
	r.Id = &id
	return r
}

// WithIndex sets the Index
func (r *ReportingDescriptorReference) WithIndex(index int) *ReportingDescriptorReference {
	i := uint(index)
	r.Index = &i
	return r
}

// WithGuid sets the Guid
func (r *ReportingDescriptorReference) WithGuid(guid string) *ReportingDescriptorReference {
	r.Guid = &guid
	return r
}

// WithToolComponentReference sets the ToolComponentReference
func (r *ReportingDescriptorReference) WithToolComponentReference(toolComponentRef *ToolComponentReference) *ReportingDescriptorReference {
	r.ToolComponent = toolComponentRef
	return r
}
