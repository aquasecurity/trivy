package types

import ftypes "github.com/aquasecurity/fanal/types"

// DetectedMisconfiguration holds detected misconfigurations
type DetectedMisconfiguration struct {
	Type       string        `json:",omitempty"`
	ID         string        `json:",omitempty"`
	Title      string        `json:",omitempty"`
	Message    string        `json:",omitempty"`
	Severity   string        `json:",omitempty"`
	PrimaryURL string        `json:",omitempty"`
	Status     MisconfStatus `json:",omitempty"`
	Layer      ftypes.Layer  `json:",omitempty"`
}

type MisconfStatus string

const (
	StatusPassed    MisconfStatus = "PASS"
	StatusFailure   MisconfStatus = "FAIL"
	StatusException MisconfStatus = "EXCEPTION"
)
