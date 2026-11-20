package elb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elb.ELB
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_alb" "example" {
				name               = "good_alb"
				internal           = true
				load_balancer_type = "application"
				
				access_logs {
				  bucket  = aws_s3_bucket.lb_logs.bucket
				  prefix  = "test-lb"
				  enabled = true
				}
			  
				drop_invalid_header_fields = true
			  }

			  resource "aws_alb_listener" "example" {
				load_balancer_arn = aws_alb.example.arn
				protocol = "HTTPS"
				ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"

				default_action {
					type             = "forward"
				}
			}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type:                    iacTypes.StringTest("application"),
						DropInvalidHeaderFields: iacTypes.BoolTest(true),
						Internal:                iacTypes.BoolTest(true),
						Listeners: []elb.Listener{
							{
								Protocol:  iacTypes.StringTest("HTTPS"),
								TLSPolicy: iacTypes.StringTest("ELBSecurityPolicy-TLS-1-1-2017-01"),
								DefaultActions: []elb.Action{
									{
										Type: iacTypes.StringTest("forward"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_alb" "example" {
			}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("application"),
					},
				},
			},
		},
		{
			name: "https listener without ssl policy",
			terraform: `
resource "aws_lb" "example" {
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "HTTPS"
}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("application"),
						Listeners: []elb.Listener{
							{
								Protocol:  iacTypes.StringTest("HTTPS"),
								TLSPolicy: iacTypes.StringTest(elb.DefaultTLSPolicy),
							},
						},
					},
				},
			},
		},
		{
			name: "lowercase https listener without ssl policy",
			terraform: `
resource "aws_lb" "example" {
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "https"
}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("application"),
						Listeners: []elb.Listener{
							{
								Protocol:  iacTypes.StringTest("https"),
								TLSPolicy: iacTypes.StringTest(elb.DefaultTLSPolicy),
							},
						},
					},
				},
			},
		},
		{
			name: "http listener without ssl policy",
			terraform: `
resource "aws_lb" "example" {
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("application"),
						Listeners: []elb.Listener{
							{
								Protocol: iacTypes.StringTest("HTTP"),
							},
						},
					},
				},
			},
		},
		{
			name: "network load balancer listeners",
			terraform: `
resource "aws_lb" "example" {
  load_balancer_type = "network"
}

resource "aws_lb_listener" "tls" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "TLS"
}

resource "aws_lb_listener" "tls_with_policy" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_lb_listener" "tcp" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "TCP"
}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("network"),
						Listeners: []elb.Listener{
							{
								Protocol: iacTypes.StringTest("TCP"),
							},
							{
								Protocol:  iacTypes.StringTest("TLS"),
								TLSPolicy: iacTypes.StringTest(elb.DefaultTLSPolicy),
							},
							{
								Protocol:  iacTypes.StringTest("TLS"),
								TLSPolicy: iacTypes.StringTest("ELBSecurityPolicy-TLS13-1-2-2021-06"),
							},
						},
					},
				},
			},
		},
		{
			name: "gateway load balancer listener",
			terraform: `
resource "aws_lb" "example" {
  load_balancer_type = "gateway"
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
}
`,
			expected: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Type: iacTypes.StringTest("gateway"),
						Listeners: []elb.Listener{
							{},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestAdaptListenerTLSPolicy(t *testing.T) {
	tests := []struct {
		name               string
		listener           string
		expectedValue      string
		expectedResolvable bool
		expectedDefault    bool
	}{
		{
			name: "default policy is marked as default",
			listener: `
  protocol = "HTTPS"`,
			expectedValue:      elb.DefaultTLSPolicy,
			expectedResolvable: true,
			expectedDefault:    true,
		},
		{
			name: "no default policy for unresolvable protocol",
			listener: `
  protocol = var.unknown`,
			expectedResolvable: true,
			expectedDefault:    true,
		},
		{
			name: "unresolvable ssl policy is kept",
			listener: `
  protocol   = "HTTPS"
  ssl_policy = var.unknown`,
			expectedResolvable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `
variable "unknown" {}

resource "aws_lb" "example" {
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn` + tt.listener + `
}
`
			modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
			adapted := Adapt(modules)

			require.Len(t, adapted.LoadBalancers, 1)
			require.Len(t, adapted.LoadBalancers[0].Listeners, 1)
			policy := adapted.LoadBalancers[0].Listeners[0].TLSPolicy
			assert.Equal(t, tt.expectedValue, policy.Value())
			assert.Equal(t, tt.expectedResolvable, policy.GetMetadata().IsResolvable())
			if tt.expectedResolvable {
				assert.Equal(t, tt.expectedDefault, policy.GetMetadata().IsDefault())
			}
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_alb" "example" {
		name               = "good_alb"
		internal           = true
		load_balancer_type = "application"
		drop_invalid_header_fields = true
		
		access_logs {
		  bucket  = aws_s3_bucket.lb_logs.bucket
		  prefix  = "test-lb"
		  enabled = true
		}
	  }

	  resource "aws_alb_listener" "example" {
		load_balancer_arn = aws_alb.example.arn
		protocol = "HTTPS"
		ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"

		default_action {
			type             = "forward"
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.LoadBalancers, 1)
	loadBalancer := adapted.LoadBalancers[0]

	assert.Equal(t, 2, loadBalancer.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, loadBalancer.Metadata.Range().GetEndLine())

	assert.Equal(t, 4, loadBalancer.Internal.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, loadBalancer.Internal.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, loadBalancer.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, loadBalancer.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, loadBalancer.DropInvalidHeaderFields.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, loadBalancer.DropInvalidHeaderFields.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, loadBalancer.Listeners[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 23, loadBalancer.Listeners[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 17, loadBalancer.Listeners[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, loadBalancer.Listeners[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, loadBalancer.Listeners[0].TLSPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, loadBalancer.Listeners[0].TLSPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, loadBalancer.Listeners[0].DefaultActions[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 22, loadBalancer.Listeners[0].DefaultActions[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 21, loadBalancer.Listeners[0].DefaultActions[0].Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, loadBalancer.Listeners[0].DefaultActions[0].Type.GetMetadata().Range().GetEndLine())

}
