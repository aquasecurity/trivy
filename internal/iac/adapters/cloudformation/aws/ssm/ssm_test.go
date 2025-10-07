package ssm

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ssm.SSM
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MySecretA:
    Type: 'AWS::SecretsManager::Secret'
    Properties:
      Name: MySecretForAppA
      KmsKeyId: alias/exampleAlias
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						KMSKeyID: types.StringTest("alias/exampleAlias"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MySecretA:
    Type: 'AWS::SecretsManager::Secret'
  `,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
