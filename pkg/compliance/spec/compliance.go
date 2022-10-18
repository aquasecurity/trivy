package spec

import (
	"github.com/mitchellh/mapstructure"
)

const NsaSpec = `
---
spec:
  id: "1234"
  title: nsa
  description: National Security Agency - Kubernetes Hardening Guidance
  relatedResources : 
    - http://related-resource/
  version: "1.0"
  controls:
    - name: Non-root containers
      description: 'Check that container is not running as root'
      id: '1.0'
      checks:
        - id: AVD-KSV-0001
      severity: 'MEDIUM'
    - name: Immutable container file systems
      description: 'Check that container root file system is immutable'
      id: '1.1'
      checks:
        - id: AVD-KSV-0003
      severity: 'LOW'
    - name: tzdata - new upstream version
      description: 'Bad tzdata package'
      id: '1.2'
      checks:
        - id: DLA-2424-1
      severity: 'CRITICAL'
    - name: test control check
      description: 'check non valida check'
      id: '1.3'
      checks:
        - id: AVD-2424-1
      severity: 'CRITICAL'
`

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

// UnmarshalYAML over unmarshall to add logic
func (r *ComplianceSpec) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var res map[string]interface{}
	if err := unmarshal(&res); err != nil {
		return err
	}
	err := mapstructure.Decode(res, &r)
	if err != nil {
		return err
	}
	return ValidateScanners(r.Spec.Controls)
}
