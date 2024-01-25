package rdb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DBInstance struct {
	Metadata                  defsecTypes.MisconfigMetadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	Engine                    defsecTypes.StringValue
	EngineVersion             defsecTypes.StringValue
	NetworkID                 defsecTypes.StringValue
	PublicAccess              defsecTypes.BoolValue
}
