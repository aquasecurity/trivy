package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_AdaptVPC(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "defined",
			terraform: `
			resource "aws_flow_log" "this" {
				vpc_id = aws_vpc.main.id
			}
			resource "aws_default_vpc" "default" {
				tags = {
				  Name = "Default VPC"
				}
			  }

			  resource "aws_vpc" "main" {
				cidr_block = "4.5.6.7/32"
			  }

			resource "aws_security_group" "example" {
				name        = "http"
				description = "Allow inbound HTTP traffic"
			  
				ingress {
				  description = "Rule #1"
				  from_port   = 80
				  to_port     = 80
				  protocol    = "tcp"
				  cidr_blocks = [aws_vpc.main.cidr_block]
				}

				egress {
					cidr_blocks = ["1.2.3.4/32"]
				}
			  }

			resource "aws_network_acl_rule" "example" {
				egress         = false
				protocol       = "tcp"
				from_port      = 22
				to_port        = 22
				rule_action    = "allow"
				cidr_block     = "10.0.0.0/16"
			}

			resource "aws_security_group_rule" "example" {
				type              = "ingress"
				description = "Rule #2"
				security_group_id = aws_security_group.example.id
				from_port         = 22
				to_port           = 22
				protocol          = "tcp"
				cidr_blocks = [
				  "1.2.3.4/32",
				  "4.5.6.7/32",
				]
			  }
`,
			expected: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						IsDefault:       defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						ID:              defsecTypes.String("", defsecTypes.NewTestMetadata()),
						FlowLogsEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						IsDefault:       defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						ID:              defsecTypes.String("", defsecTypes.NewTestMetadata()),
						FlowLogsEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("Allow inbound HTTP traffic", defsecTypes.NewTestMetadata()),
						IsDefault:   defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						VPCID:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),

								Description: defsecTypes.String("Rule #1", defsecTypes.NewTestMetadata()),
								CIDRs: []defsecTypes.StringValue{
									defsecTypes.String("4.5.6.7/32", defsecTypes.NewTestMetadata()),
								},
							},
							{
								Metadata: defsecTypes.NewTestMetadata(),

								Description: defsecTypes.String("Rule #2", defsecTypes.NewTestMetadata()),
								CIDRs: []defsecTypes.StringValue{
									defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
									defsecTypes.String("4.5.6.7/32", defsecTypes.NewTestMetadata()),
								},
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    defsecTypes.NewTestMetadata(),
								Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
								CIDRs: []defsecTypes.StringValue{
									defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Type:     defsecTypes.String("ingress", defsecTypes.NewTestMetadata()),
								Action:   defsecTypes.String("allow", defsecTypes.NewTestMetadata()),
								Protocol: defsecTypes.String("tcp", defsecTypes.NewTestMetadata()),
								CIDRs: []defsecTypes.StringValue{
									defsecTypes.String("10.0.0.0/16", defsecTypes.NewTestMetadata()),
								},
							},
						},
						IsDefaultRule: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_security_group" "example" {
				ingress {
				}

				egress {
				}
			  }

			resource "aws_network_acl_rule" "example" {
			}
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("Managed by Terraform", defsecTypes.NewTestMetadata()),
						IsDefault:   defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						VPCID:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    defsecTypes.NewTestMetadata(),
								Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    defsecTypes.NewTestMetadata(),
								Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Type:     defsecTypes.String("ingress", defsecTypes.NewTestMetadata()),
								Action:   defsecTypes.String("", defsecTypes.NewTestMetadata()),
								Protocol: defsecTypes.String("-1", defsecTypes.NewTestMetadata()),
							},
						},
						IsDefaultRule: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "aws_flow_log refer to locals",
			terraform: `
locals {
  vpc_id = try(aws_vpc.this.id, "")
}

resource "aws_vpc" "this" {
}

resource "aws_flow_log" "this" {
  vpc_id = local.vpc_id
}
`,
			expected: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						IsDefault:       defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						ID:              defsecTypes.String("", defsecTypes.NewTestMetadata()),
						FlowLogsEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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

func TestVPCLines(t *testing.T) {
	src := `
	resource "aws_default_vpc" "default" {
	  }

	resource "aws_vpc" "main" {
		cidr_block = "4.5.6.7/32"
	  }

	resource "aws_security_group" "example" {
		name        = "http"
		description = "Allow inbound HTTP traffic"
	  
		ingress {
		  description = "HTTP from VPC"
		  from_port   = 80
		  to_port     = 80
		  protocol    = "tcp"
		  cidr_blocks = [aws_vpc.main.cidr_block]
		}

		egress {
			cidr_blocks = ["1.2.3.4/32"]
		}
	  }

	resource "aws_security_group_rule" "example" {
		type              = "ingress"
		security_group_id = aws_security_group.example.id
		from_port         = 22
		to_port           = 22
		protocol          = "tcp"
		cidr_blocks = [
		  "1.2.3.4/32",
		  "4.5.6.7/32",
		]
	  }
	  
	  resource "aws_network_acl_rule" "example" {
		egress         = false
		protocol       = "tcp"
		from_port      = 22
		to_port        = 22
		rule_action    = "allow"
		cidr_block     = "10.0.0.0/16"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.VPCs, 2)
	require.Len(t, adapted.SecurityGroups, 1)
	require.Len(t, adapted.NetworkACLs, 1)

	defaultVPC := adapted.VPCs[0]
	securityGroup := adapted.SecurityGroups[0]
	networkACL := adapted.NetworkACLs[0]

	assert.Equal(t, 2, defaultVPC.Metadata.Range().GetStartLine())
	assert.Equal(t, 3, defaultVPC.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 24, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.IngressRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 19, securityGroup.IngressRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, securityGroup.IngressRules[1].Metadata.Range().GetStartLine())
	assert.Equal(t, 36, securityGroup.IngressRules[1].Metadata.Range().GetEndLine())

	assert.Equal(t, 32, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, securityGroup.EgressRules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 23, securityGroup.EgressRules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, networkACL.Rules[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 45, networkACL.Rules[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetEndLine())
}
