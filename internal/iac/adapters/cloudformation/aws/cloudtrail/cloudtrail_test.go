package cloudtrail

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected cloudtrail.CloudTrail
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      S3BucketName: MyBucket
      IsLogging: true
      TrailName: MyTrail
      EnableLogFileValidation: true
      IsMultiRegionTrail: true
      CloudWatchLogsLogGroupArn: cw-arn
      KmsKeyId: my-kms-key
`,
			expected: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Name:                      types.StringTest("MyTrail"),
						BucketName:                types.StringTest("MyBucket"),
						IsLogging:                 types.BoolTest(true),
						IsMultiRegion:             types.BoolTest(true),
						EnableLogFileValidation:   types.BoolTest(true),
						CloudWatchLogsLogGroupArn: types.StringTest("cw-arn"),
						KMSKeyID:                  types.StringTest("my-kms-key"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
  `,
			expected: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
