package cloudtrail

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourcesByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Metadata:                  r.Metadata(),
			Name:                      r.GetStringProperty("TrailName"),
			EnableLogFileValidation:   r.GetBoolProperty("EnableLogFileValidation"),
			IsMultiRegion:             r.GetBoolProperty("IsMultiRegionTrail"),
			KMSKeyID:                  r.GetStringProperty("KmsKeyId"),
			CloudWatchLogsLogGroupArn: r.GetStringProperty("CloudWatchLogsLogGroupArn"),
			IsLogging:                 r.GetBoolProperty("IsLogging"),
			BucketName:                r.GetStringProperty("S3BucketName"),
		}

		trails = append(trails, ct)
	}
	return trails
}
