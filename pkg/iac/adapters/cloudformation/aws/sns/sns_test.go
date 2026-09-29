package sns

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sns"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected sns.SNS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MySNSTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: mykey
`,
			expected: sns.SNS{
				Topics: []sns.Topic{
					{
						Encryption: sns.Encryption{
							KMSKeyID: types.StringTest("mykey"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MySNSTopic:
    Type: AWS::SNS::Topic
  `,
			expected: sns.SNS{
				Topics: []sns.Topic{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
