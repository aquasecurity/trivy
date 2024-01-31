package spec

import (
	"github.com/aquasecurity/trivy/pkg/iac/specs"
)

// Loader access compliance specs
type Loader interface {
	GetSpecByName(name string) string
}

type specLoader struct {
}

// NewSpecLoader instansiate spec loader
func NewSpecLoader() Loader {
	return &specLoader{}
}

// GetSpecByName get spec name and return spec data
func (sl specLoader) GetSpecByName(name string) string {
	return specs.GetSpec(name)
}
