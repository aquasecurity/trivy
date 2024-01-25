package monitor

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	Metadata        defsecTypes.MisconfigMetadata
	RetentionPolicy RetentionPolicy
	Categories      []defsecTypes.StringValue
	Locations       []defsecTypes.StringValue
}

type RetentionPolicy struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	Days     defsecTypes.IntValue
}
