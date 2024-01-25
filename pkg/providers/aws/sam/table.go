package sam

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SimpleTable struct {
	Metadata         defsecTypes.MisconfigMetadata
	TableName        defsecTypes.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	Metadata defsecTypes.MisconfigMetadata

	Enabled        defsecTypes.BoolValue
	KMSMasterKeyID defsecTypes.StringValue
}
