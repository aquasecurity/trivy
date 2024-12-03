package iam

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptUsers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.User
	}{
		{
			name: "policy",
			terraform: `
resource "aws_iam_user" "lb" {
  name = "loadbalancer"
  path = "/system/"
}

resource "aws_iam_user_policy" "policy" {
  name = "test"
  user = aws_iam_user.lb.name


  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
`,
			expected: []iam.User{
				{
					Metadata:   iacTypes.NewTestMetadata(),
					Name:       iacTypes.String("loadbalancer", iacTypes.NewTestMetadata()),
					LastAccess: iacTypes.TimeUnresolvable(iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
							Builtin:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "policy attachment",
			terraform: `
resource "aws_iam_user" "user" {
  name = "test-user"
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "test-attach" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.User{
				{
					Metadata:   iacTypes.NewTestMetadata(),
					Name:       iacTypes.String("test-user", iacTypes.NewTestMetadata()),
					LastAccess: iacTypes.TimeUnresolvable(iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
							Builtin:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "access key",
			terraform: `
resource "aws_iam_access_key" "lb" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
  status  = "Active"
}

resource "aws_iam_user" "lb" {
  name = "loadbalafncer"
  path = "/system/"
}
`,
			expected: []iam.User{
				{
					Metadata:   iacTypes.NewTestMetadata(),
					Name:       iacTypes.String("loadbalafncer", iacTypes.NewTestMetadata()),
					LastAccess: iacTypes.TimeUnresolvable(iacTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Active:   iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "access key with default status",
			terraform: `
resource "aws_iam_access_key" "lb" {
  user    = aws_iam_user.lb.name
  pgp_key = "keybase:some_person_that_exists"
}

resource "aws_iam_user" "lb" {
  name = "loadbalafncer"
  path = "/system/"
}
`,
			expected: []iam.User{
				{
					Metadata:   iacTypes.NewTestMetadata(),
					Name:       iacTypes.String("loadbalafncer", iacTypes.NewTestMetadata()),
					LastAccess: iacTypes.TimeUnresolvable(iacTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Active:   iacTypes.BoolDefault(true, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptUsers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
