package cloudwatch

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected cloudwatch.CloudWatch
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  myLogGroup: 
    Type: AWS::Logs::LogGroup
    Properties: 
      LogGroupName: my-log-group
      RetentionInDays: 7
      KmsKeyId: my-kms

`,
			expected: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Name:            types.StringTest("my-log-group"),
						RetentionInDays: types.IntTest(7),
						KMSKeyID:        types.StringTest("my-kms"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  myLogGroup: 
    Type: AWS::Logs::LogGroup
  `,
			expected: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
