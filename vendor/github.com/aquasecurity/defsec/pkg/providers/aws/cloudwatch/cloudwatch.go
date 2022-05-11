package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type CloudWatch struct {
	LogGroups []LogGroup
}

type LogGroup struct {
	types.Metadata
	Name            types.StringValue
	KMSKeyID        types.StringValue
	RetentionInDays types.IntValue
}
