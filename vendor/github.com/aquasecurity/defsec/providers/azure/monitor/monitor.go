package monitor

import "github.com/aquasecurity/defsec/parsers/types"

type Monitor struct {
	types.Metadata
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
