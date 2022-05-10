package sarif

// Conversion ...
type Conversion struct {
	AnalysisToolLogFiles []*ArtifactLocation `json:"analysisToolLogFiles,omitempty"`
	Invocation           *Invocation         `json:"invocation,omitempty"`
	Tool                 *Tool               `json:"tool"`
	PropertyBag

}

// NewConversion creates a new Conversion and returns a pointer to it
func NewConversion() *Conversion {
	return &Conversion{}
}

// WithInvocation sets the Invocation
func (conversion *Conversion) WithInvocation(invocation *Invocation) *Conversion {
	conversion.Invocation = invocation
	return conversion
}

// WithTool sets the Tool
func (conversion *Conversion) WithTool(tool *Tool) *Conversion {
	conversion.Tool = tool
	return conversion
}
