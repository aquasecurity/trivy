package eks

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected eks.EKS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  EKSCluster:
      Type: AWS::EKS::Cluster
      Properties:
        Logging:
          ClusterLogging:
            EnabledTypes:
              - Type: api
              - Type: audit
              - Type: authenticator
              - Type: controllerManager
              - Type: scheduler
        EncryptionConfig:
          - Provider:
              KeyArn: alias/mykey
            Resources: [secrets]
        ResourcesVpcConfig:
          EndpointPublicAccess: True
          PublicAccessCidrs:
            - 0.0.0.0/0
`,
			expected: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Logging: eks.Logging{
							API:               types.BoolTest(true),
							Audit:             types.BoolTest(true),
							Authenticator:     types.BoolTest(true),
							ControllerManager: types.BoolTest(true),
							Scheduler:         types.BoolTest(true),
						},
						Encryption: eks.Encryption{
							KMSKeyID: types.StringTest("alias/mykey"),
							Secrets:  types.BoolTest(true),
						},
						PublicAccessEnabled: types.BoolTest(true),
						PublicAccessCIDRs: []types.StringValue{
							types.StringTest("0.0.0.0/0"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  EKSCluster:
      Type: AWS::EKS::Cluster
  `,
			expected: eks.EKS{
				Clusters: []eks.Cluster{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
