package cloudwatch

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type CloudWatch struct {
	LogGroups []LogGroup
	Alarms    []Alarm
}

type Alarm struct {
	Metadata   iacTypes.Metadata
	AlarmName  iacTypes.StringValue
	MetricName iacTypes.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Value    iacTypes.StringValue
}

type MetricFilter struct {
	Metadata      iacTypes.Metadata
	FilterName    iacTypes.StringValue
	FilterPattern iacTypes.StringValue
}

type MetricDataQuery struct {
	Metadata   iacTypes.Metadata
	Expression iacTypes.StringValue
	ID         iacTypes.StringValue
}

type LogGroup struct {
	Metadata        iacTypes.Metadata
	Arn             iacTypes.StringValue
	Name            iacTypes.StringValue
	KMSKeyID        iacTypes.StringValue
	RetentionInDays iacTypes.IntValue
	MetricFilters   []MetricFilter
}
