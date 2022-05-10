package cloudwatch

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws/cloudwatch"
)

func Adapt(modules terraform.Modules) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{
		LogGroups: adaptLogGroups(modules),
	}
}

func adaptLogGroups(modules terraform.Modules) []cloudwatch.LogGroup {
	var logGroups []cloudwatch.LogGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_log_group") {
			logGroups = append(logGroups, adaptLogGroup(resource))
		}
	}
	return logGroups
}

func adaptLogGroup(resource *terraform.Block) cloudwatch.LogGroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return cloudwatch.LogGroup{
		Metadata:        resource.GetMetadata(),
		Name:            nameVal,
		KMSKeyID:        KMSKeyIDVal,
		RetentionInDays: retentionInDaysVal,
	}
}
