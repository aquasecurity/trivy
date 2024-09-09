package types

import (
	"encoding/json"

	"golang.org/x/xerrors"
)

type FindingType string
type FindingStatus string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeSecret           FindingType = "secret"
	FindingTypeLicense          FindingType = "license"

	FindingStatusIgnored            FindingStatus = "ignored"             // Trivy
	FindingStatusUnknown            FindingStatus = "unknown"             // Trivy
	FindingStatusNotAffected        FindingStatus = "not_affected"        // VEX
	FindingStatusAffected           FindingStatus = "affected"            // VEX
	FindingStatusFixed              FindingStatus = "fixed"               // VEX
	FindingStatusUnderInvestigation FindingStatus = "under_investigation" // VEX
)

// Finding represents one of the findings that Trivy can detect,
// such as vulnerabilities, misconfigurations, secrets, and licenses.
type finding interface {
	findingType() FindingType
}

// ModifiedFinding represents a security finding that has been modified by an external source,
// such as .trivyignore and VEX. Currently, it is primarily used to account for vulnerabilities
// that are ignored via .trivyignore or identified as not impactful through VEX.
// However, it is planned to also store vulnerabilities whose severity has been adjusted by VEX,
// or that have been detected through Wasm modules in the future.
type ModifiedFinding struct {
	Type      FindingType
	Status    FindingStatus
	Statement string
	Source    string
	Finding   finding // one of findings
}

func NewModifiedFinding(f finding, status FindingStatus, statement, source string) ModifiedFinding {
	return ModifiedFinding{
		Type:      f.findingType(),
		Status:    status,
		Statement: statement,
		Source:    source,
		Finding:   f,
	}
}

// MarshalJSON correctly marshals ModifiedFinding.Finding given the type and `MarshalJSON` functions of struct fields
func (m *ModifiedFinding) MarshalJSON() ([]byte, error) {
	var raw struct {
		Type      FindingType     `json:"Type"`
		Status    FindingStatus   `json:"Status"`
		Statement string          `json:"Statement"`
		Source    string          `json:"Source"`
		Finding   json.RawMessage `json:"Finding"`
	}
	raw.Type = m.Type
	raw.Status = m.Status
	raw.Statement = m.Statement
	raw.Source = m.Source

	// Define a `Finding` type and marshal as a struct of that type.
	// This is necessary to run the `MarshalJSON` functions on the struct fields.
	var err error
	switch val := m.Finding.(type) {
	case DetectedVulnerability:
		if raw.Finding, err = json.Marshal(&val); err != nil {
			return nil, xerrors.Errorf("unable to marshal `DetectedVulnerability` Findings: %w", err)
		}
	case DetectedMisconfiguration:
		if raw.Finding, err = json.Marshal(&val); err != nil {
			return nil, xerrors.Errorf("unable to marshal `DetectedMisconfiguration` Findings: %w", err)
		}
	case DetectedSecret:
		if raw.Finding, err = json.Marshal(&val); err != nil {
			return nil, xerrors.Errorf("unable to marshal `DetectedSecret` Findings: %w", err)
		}
	case DetectedLicense:
		if raw.Finding, err = json.Marshal(&val); err != nil {
			return nil, xerrors.Errorf("unable to marshal `DetectedLicense` Findings: %w", err)
		}
	default:
		return nil, xerrors.Errorf("invalid Finding type: %T", val)
	}

	return json.Marshal(&raw)
}

// UnmarshalJSON unmarshals ModifiedFinding given the type and `UnmarshalJSON` functions of struct fields
func (m *ModifiedFinding) UnmarshalJSON(data []byte) error {
	raw := struct {
		Type      FindingType     `json:"Type"`
		Status    FindingStatus   `json:"Status"`
		Statement string          `json:"Statement"`
		Source    string          `json:"Source"`
		Finding   json.RawMessage `json:"Finding"`
	}{}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	m.Type = raw.Type
	m.Status = raw.Status
	m.Statement = raw.Statement
	m.Source = raw.Source

	// Select struct by m.Type to avoid errors with Unmarshal
	switch m.Type {
	case FindingTypeVulnerability:
		rawFinding := DetectedVulnerability{}
		if err := json.Unmarshal(raw.Finding, &rawFinding); err != nil {
			return xerrors.Errorf("unable to unmarshal %q type: %w", m.Type, err)
		}
		m.Finding = rawFinding
	case FindingTypeMisconfiguration:
		rawFinding := DetectedMisconfiguration{}
		if err := json.Unmarshal(raw.Finding, &rawFinding); err != nil {
			return xerrors.Errorf("unable to unmarshal %q type: %w", m.Type, err)
		}
		m.Finding = rawFinding
	case FindingTypeSecret:
		rawFinding := DetectedSecret{}
		if err := json.Unmarshal(raw.Finding, &rawFinding); err != nil {
			return xerrors.Errorf("unable to unmarshal %q type: %w", m.Type, err)
		}
		m.Finding = rawFinding
	case FindingTypeLicense:
		rawFinding := DetectedLicense{}
		if err := json.Unmarshal(raw.Finding, &rawFinding); err != nil {
			return xerrors.Errorf("unable to unmarshal %q type: %w", m.Type, err)
		}
		m.Finding = rawFinding
	default:
		return xerrors.Errorf("invalid Finding type: %s", m.Type)
	}

	return nil
}
