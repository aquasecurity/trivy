package cloudwatch

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type CloudWatch struct {
	LogGroups []LogGroup
	Alarms    []Alarm
}

func (w CloudWatch) GetLogGroupByArn(arn string) (logGroup *LogGroup) {
	for _, logGroup := range w.LogGroups {
		if logGroup.Arn.EqualTo(arn) {
			return &logGroup
		}
	}
	return nil
}

func (w CloudWatch) GetAlarmByMetricName(metricName string) (alarm *Alarm) {
	for _, alarm := range w.Alarms {
		if alarm.MetricName.EqualTo(metricName) {
			return &alarm
		}
	}
	return nil
}

type Alarm struct {
	Metadata   defsecTypes.Metadata
	AlarmName  defsecTypes.StringValue
	MetricName defsecTypes.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Value    defsecTypes.StringValue
}

type MetricFilter struct {
	Metadata      defsecTypes.Metadata
	FilterName    defsecTypes.StringValue
	FilterPattern defsecTypes.StringValue
}

type MetricDataQuery struct {
	Metadata   defsecTypes.Metadata
	Expression defsecTypes.StringValue
	ID         defsecTypes.StringValue
}

type LogGroup struct {
	Metadata        defsecTypes.Metadata
	Arn             defsecTypes.StringValue
	Name            defsecTypes.StringValue
	KMSKeyID        defsecTypes.StringValue
	RetentionInDays defsecTypes.IntValue
	MetricFilters   []MetricFilter
}
