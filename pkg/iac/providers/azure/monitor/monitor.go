package monitor

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	Metadata        iacTypes.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []iacTypes.StringValue
	Locations       []iacTypes.StringValue
}

type RetentionPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	Days     iacTypes.IntValue
}
