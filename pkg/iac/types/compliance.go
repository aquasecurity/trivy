package types

type Severity string
type ControlStatus string

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `yaml:"id"`
}

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec Spec `yaml:"spec"`
}

type Spec struct {
	ID               string    `yaml:"id"`
	Title            string    `yaml:"title"`
	Description      string    `yaml:"description"`
	Version          string    `yaml:"version"`
	RelatedResources []string  `yaml:"relatedResources"`
	Controls         []Control `yaml:"controls"`
}

// Control represent the cps controls data and mapping checks
type Control struct {
	ID            string        `yaml:"id"`
	Name          string        `yaml:"name"`
	Description   string        `yaml:"description,omitempty"`
	Checks        []SpecCheck   `yaml:"checks"`
	Severity      Severity      `yaml:"severity"`
	DefaultStatus ControlStatus `yaml:"defaultStatus,omitempty"`
}
