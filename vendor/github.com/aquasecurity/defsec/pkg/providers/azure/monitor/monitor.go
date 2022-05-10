package monitor

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	types.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []types.StringValue
	Locations       []types.StringValue
}

type RetentionPolicy struct {
	types.Metadata
	Enabled types.BoolValue
	Days    types.IntValue
}
