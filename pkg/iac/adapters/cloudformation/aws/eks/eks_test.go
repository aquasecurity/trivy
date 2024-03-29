package eks

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
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
`,
			expected: eks.EKS{
				Clusters: []eks.Cluster{{}},
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
