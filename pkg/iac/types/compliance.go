package types

type Severity string
type ControlStatus string

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `yaml:"id"`
}
type Command struct {
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
	Platform         string    `yaml:"platform"`
	Type             string    `yaml:"type"`
	RelatedResources []string  `yaml:"relatedResources,omitempty"`
	Controls         []Control `yaml:"controls"`
}

// Control represent the cps controls data and mapping checks
type Control struct {
	ID            string        `yaml:"id"`
	Name          string        `yaml:"name"`
	Description   string        `yaml:"description,omitempty"`
	Checks        []SpecCheck   `yaml:"checks,omitempty"`
	Commands      []Command     `yaml:"commands,omitempty"`
	Severity      Severity      `yaml:"severity"`
	DefaultStatus ControlStatus `yaml:"defaultStatus,omitempty"`
}
