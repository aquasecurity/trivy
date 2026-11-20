package elb

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected elb.ELB
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    DependsOn:
      - ALBLogsBucketPermission
    Properties:
      Name: "k8s-dev"
      Scheme: internal
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
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
        - Type: 'redirect'
          RedirectConfig:
            Port: 443
            Protocol: HTTPS
            StatusCode: HTTP_302
      LoadBalancerArn: !Ref LoadBalancer
      Protocol: HTTPS
      SslPolicy: "ELBSecurityPolicy-TLS-1-2-2017-01"
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type:                    types.StringTest("application"),
						DropInvalidHeaderFields: types.BoolTest(true),
						Internal:                types.BoolTest(true),
						Listeners: []elb.Listener{
							{
								Protocol:  types.StringTest("HTTPS"),
								TLSPolicy: types.StringTest("ELBSecurityPolicy-TLS-1-2-2017-01"),
								DefaultActions: []elb.Action{
									{
										Type: types.StringTest("redirect"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "https listener without ssl policy",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Protocol: HTTPS
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: types.StringTest("application"),
						Listeners: []elb.Listener{
							{
								Protocol:  types.StringTest("HTTPS"),
								TLSPolicy: types.StringTest(elb.DefaultTLSPolicy),
							},
						},
					},
				},
			},
		},
		{
			name: "http listener without ssl policy",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Protocol: HTTP
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: types.StringTest("application"),
						Listeners: []elb.Listener{
							{
								Protocol: types.StringTest("HTTP"),
							},
						},
					},
				},
			},
		},
		{
			name: "tls listener without ssl policy",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: network
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Protocol: TLS
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: types.StringTest("network"),
						Listeners: []elb.Listener{
							{
								Protocol:  types.StringTest("TLS"),
								TLSPolicy: types.StringTest(elb.DefaultTLSPolicy),
							},
						},
					},
				},
			},
		},
		{
			name: "tcp listener without ssl policy",
			source: `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: network
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Protocol: TCP
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: types.StringTest("network"),
						Listeners: []elb.Listener{
							{
								Protocol: types.StringTest("TCP"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
