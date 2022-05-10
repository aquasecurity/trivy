package cloudwatch

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/cloudwatch"
)

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourceByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("LogGroupName"),
			KMSKeyID: r.GetStringProperty("KmsKeyId"),
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}
