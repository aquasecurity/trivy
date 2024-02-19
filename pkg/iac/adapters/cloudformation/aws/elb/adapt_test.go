package elb

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/require"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected elb.ELB
	}{
		{
			name: "LoadBalancer",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    DependsOn:
      - ALBLogsBucketPermission
    Properties:
      Name: "k8s-dev"
      IpAddressType: ipv4
      LoadBalancerAttributes:
        - Key: routing.http2.enabled
          Value: "true"
        - Key: deletion_protection.enabled
          Value: "true"
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: "true"
        - Key: access_logs.s3.enabled
          Value: "true"
      Tags:
        - Key: ingress.k8s.aws/resource
          Value: LoadBalancer
        - Key: elbv2.k8s.aws/cluster
          Value: "biomage-dev"
      Type: application
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                types.NewTestMetadata(),
						Type:                    types.String("application", types.NewTestMetadata()),
						DropInvalidHeaderFields: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := testutil.CreateFS(t, map[string]string{
				"template.yaml": tt.source,
			})

			p := parser.New()
			fctx, err := p.ParseFile(context.TODO(), fs, "template.yaml")
			require.NoError(t, err)

			testutil.AssertDefsecEqual(t, tt.expected, Adapt(*fctx))
		})
	}
}
