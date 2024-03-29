package ec2

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
						Metadata:        iacTypes.NewTestMetadata(),
						IsDefault:       iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						ID:              iacTypes.String("", iacTypes.NewTestMetadata()),
						FlowLogsEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					},
					{
						Metadata:        iacTypes.NewTestMetadata(),
						IsDefault:       iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						ID:              iacTypes.String("", iacTypes.NewTestMetadata()),
						FlowLogsEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    iacTypes.NewTestMetadata(),
						Description: iacTypes.String("Allow inbound HTTP traffic", iacTypes.NewTestMetadata()),
						IsDefault:   iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						VPCID:       iacTypes.String("", iacTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: iacTypes.NewTestMetadata(),

								Description: iacTypes.String("Rule #1", iacTypes.NewTestMetadata()),
								CIDRs: []iacTypes.StringValue{
									iacTypes.String("4.5.6.7/32", iacTypes.NewTestMetadata()),
								},
							},
							{
								Metadata: iacTypes.NewTestMetadata(),

								Description: iacTypes.String("Rule #2", iacTypes.NewTestMetadata()),
								CIDRs: []iacTypes.StringValue{
									iacTypes.String("1.2.3.4/32", iacTypes.NewTestMetadata()),
									iacTypes.String("4.5.6.7/32", iacTypes.NewTestMetadata()),
								},
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    iacTypes.NewTestMetadata(),
								Description: iacTypes.String("", iacTypes.NewTestMetadata()),
								CIDRs: []iacTypes.StringValue{
									iacTypes.String("1.2.3.4/32", iacTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Type:     iacTypes.String("ingress", iacTypes.NewTestMetadata()),
								Action:   iacTypes.String("allow", iacTypes.NewTestMetadata()),
								Protocol: iacTypes.String("tcp", iacTypes.NewTestMetadata()),
								CIDRs: []iacTypes.StringValue{
									iacTypes.String("10.0.0.0/16", iacTypes.NewTestMetadata()),
								},
							},
						},
						IsDefaultRule: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
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
						Metadata:    iacTypes.NewTestMetadata(),
						Description: iacTypes.String("Managed by Terraform", iacTypes.NewTestMetadata()),
						IsDefault:   iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						VPCID:       iacTypes.String("", iacTypes.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    iacTypes.NewTestMetadata(),
								Description: iacTypes.String("", iacTypes.NewTestMetadata()),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    iacTypes.NewTestMetadata(),
								Description: iacTypes.String("", iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Type:     iacTypes.String("ingress", iacTypes.NewTestMetadata()),
								Action:   iacTypes.String("", iacTypes.NewTestMetadata()),
								Protocol: iacTypes.String("-1", iacTypes.NewTestMetadata()),
							},
						},
						IsDefaultRule: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
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
						Metadata:        iacTypes.NewTestMetadata(),
						IsDefault:       iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						ID:              iacTypes.String("", iacTypes.NewTestMetadata()),
						FlowLogsEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
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
