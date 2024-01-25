package cloudwatch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourcesByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Metadata:        r.Metadata(),
			Arn:             types.StringDefault("", r.Metadata()),
			Name:            r.GetStringProperty("LogGroupName"),
			KMSKeyID:        r.GetStringProperty("KmsKeyId"),
			RetentionInDays: r.GetIntProperty("RetentionInDays", 0),
			MetricFilters:   nil,
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}
