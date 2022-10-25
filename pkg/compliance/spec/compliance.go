package spec

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"

	SeverityNone    Severity = "NONE"
	SeverityUnknown Severity = "UNKNOWN"
)

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

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `yaml:"id"`
}

// ControlCheck provides the result of conducting a single audit step.
type ControlCheck struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	PassTotal   int      `yaml:"passTotal"`
	FailTotal   int      `yaml:"failTotal"`
	Severity    Severity `yaml:"severity"`
}

type ControlStatus string

const (
	FailStatus ControlStatus = "FAIL"
	PassStatus ControlStatus = "PASS"
	WarnStatus ControlStatus = "WARN"
)
