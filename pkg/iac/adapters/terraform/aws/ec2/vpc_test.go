package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_AdaptVPC(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "defined",
			terraform: `resource "aws_flow_log" "this" {
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
  egress      = false
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  rule_action = "allow"
  cidr_block  = "10.0.0.0/16"
}

resource "aws_security_group_rule" "example" {
  type              = "ingress"
  description       = "Rule #2"
  security_group_id = aws_security_group.example.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks = [
    "1.2.3.4/32",
    "4.5.6.7/32",
  ]
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
			expected: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						IsDefault: iacTypes.BoolTest(true),
					},
					{
						FlowLogsEnabled: iacTypes.BoolTest(true),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						Description: iacTypes.StringTest("Allow inbound HTTP traffic"),
						IngressRules: []ec2.SecurityGroupRule{
							{

								Description: iacTypes.StringTest("Rule #1"),
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("4.5.6.7/32"),
								},
								FromPort: iacTypes.IntTest(80),
								ToPort:   iacTypes.IntTest(80),
								Protocol: iacTypes.StringTest("tcp"),
							},
							{

								Description: iacTypes.StringTest("Rule #2"),
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("1.2.3.4/32"),
									iacTypes.StringTest("4.5.6.7/32"),
								},
								FromPort: iacTypes.IntTest(22),
								ToPort:   iacTypes.IntTest(22),
								Protocol: iacTypes.StringTest("tcp"),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("1.2.3.4/32"),
								},
								FromPort: iacTypes.IntTest(-1),
								ToPort:   iacTypes.IntTest(-1),
							},
						},
					},
					{
						IsDefault: iacTypes.BoolTest(true),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Protocol: iacTypes.StringTest("-1"),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								Protocol: iacTypes.StringTest("-1"),
								CIDRs:    []iacTypes.StringValue{iacTypes.StringTest("0.0.0.0/0")},
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Rules: []ec2.NetworkACLRule{
							{
								Type:     iacTypes.StringTest("ingress"),
								Action:   iacTypes.StringTest("allow"),
								Protocol: iacTypes.StringTest("tcp"),
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("10.0.0.0/16"),
								},
								FromPort: iacTypes.IntTest(22),
								ToPort:   iacTypes.IntTest(22),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `resource "aws_security_group" "example" {
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
						Description: iacTypes.StringTest("Managed by Terraform"),
						IngressRules: []ec2.SecurityGroupRule{
							{
								FromPort: iacTypes.IntTest(-1),
								ToPort:   iacTypes.IntTest(-1),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								FromPort: iacTypes.IntTest(-1),
								ToPort:   iacTypes.IntTest(-1),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Rules: []ec2.NetworkACLRule{
							{
								Type:     iacTypes.StringTest("ingress"),
								FromPort: iacTypes.IntTest(-1),
								ToPort:   iacTypes.IntTest(-1),
							},
						},
					},
				},
			},
		},
		{
			name: "aws_flow_log refer to locals",
			terraform: `locals {
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
						FlowLogsEnabled: iacTypes.BoolTest(true),
					},
				},
			},
		},
		{
			name: "ingress and egress rules",
			terraform: `resource "aws_security_group" "example" {
  name        = "example"
  description = "example"
}

resource "aws_vpc_security_group_egress_rule" "test" {
  security_group_id = aws_security_group.example.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_ingress_rule" "test" {
  security_group_id = aws_security_group.example.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = "22"
  to_port           = "22"
  ip_protocol       = "tcp"
}
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Description: iacTypes.StringTest("example"),
						IngressRules: []ec2.SecurityGroupRule{
							{
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("0.0.0.0/0"),
								},
								Protocol: iacTypes.StringTest("tcp"),
								FromPort: iacTypes.IntTest(22),
								ToPort:   iacTypes.IntTest(22),
							},
						},
						EgressRules: []ec2.SecurityGroupRule{
							{
								CIDRs: []iacTypes.StringValue{
									iacTypes.StringTest("0.0.0.0/0"),
								},
								Protocol: iacTypes.StringTest("-1"),
								FromPort: iacTypes.IntTest(-1),
								ToPort:   iacTypes.IntTest(-1),
							},
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
  egress      = false
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  rule_action = "allow"
  cidr_block  = "10.0.0.0/16"
}
`

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
