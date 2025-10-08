package types

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Report represents a kubernetes scan report
type Report struct {
	ID               string
	Title            string
	Description      string
	Version          string
	RelatedResources []string
	Results          []*ControlCheckResult
}

func (r Report) Empty() bool {
	return len(r.Results) == 0
}

type ControlCheckResult struct {
	ID            string
	Name          string
	Description   string
	DefaultStatus iacTypes.ControlStatus `json:",omitempty"`
	Severity      string
	Results       types.Results
}

// SummaryReport represents a kubernetes scan report with consolidated findings
type SummaryReport struct {
	SchemaVersion   int `json:",omitempty"`
	ID              string
	Title           string
	SummaryControls []ControlCheckSummary `json:",omitempty"`
}

type ControlCheckSummary struct {
	ID        string
	Name      string
	Severity  string
	TotalFail *int `json:",omitempty"`
}
