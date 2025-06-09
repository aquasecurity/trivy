package types

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

// DetectedMisconfiguration holds detected misconfigurations
type DetectedMisconfiguration struct {
	Type          string               `json:",omitempty"`
	ID            string               `json:",omitempty"`
	AVDID         string               `json:",omitempty"`
	Title         string               `json:",omitempty"`
	Description   string               `json:",omitempty"`
	Message       string               `json:",omitempty"`
	Namespace     string               `json:",omitempty"`
	Query         string               `json:",omitempty"`
	Resolution    string               `json:",omitempty"`
	Severity      string               `json:",omitempty"`
	PrimaryURL    string               `json:",omitempty"`
	References    []string             `json:",omitempty"`
	Status        MisconfStatus        `json:",omitempty"`
	Layer         ftypes.Layer         `json:",omitempty"`
	CauseMetadata ftypes.CauseMetadata `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

// MisconfStatus represents a status of misconfiguration
type MisconfStatus string

const (
	// MisconfStatusPassed represents successful status
	MisconfStatusPassed MisconfStatus = "PASS"

	// MisconfStatusFailure represents failure status
	MisconfStatusFailure MisconfStatus = "FAIL"

	// MisconfStatusException Passed represents the status of exception
	MisconfStatusException MisconfStatus = "EXCEPTION"
)

func (DetectedMisconfiguration) findingType() FindingType { return FindingTypeMisconfiguration }
