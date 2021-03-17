package types

import ftypes "github.com/aquasecurity/fanal/types"

// DetectedMisconfiguration holds detected misconfigurations
type DetectedMisconfiguration struct {
	Type       string       `json:",omitempty"`
	ID         string       `json:",omitempty"`
	Message    string       `json:",omitempty"`
	Severity   string       `json:",omitempty"`
	PrimaryURL string       `json:",omitempty"`
	Layer      ftypes.Layer `json:",omitempty"`
}
