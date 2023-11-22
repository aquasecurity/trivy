package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
					Metadata:   defsecTypes.NewTestMetadata(),
					Name:       defsecTypes.String("loadbalancer", defsecTypes.NewTestMetadata()),
					LastAccess: defsecTypes.TimeUnresolvable(defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("test", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
							Builtin:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
					Metadata:   defsecTypes.NewTestMetadata(),
					Name:       defsecTypes.String("test-user", defsecTypes.NewTestMetadata()),
					LastAccess: defsecTypes.TimeUnresolvable(defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("test-policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
							Builtin:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
					Metadata:   defsecTypes.NewTestMetadata(),
					Name:       defsecTypes.String("loadbalafncer", defsecTypes.NewTestMetadata()),
					LastAccess: defsecTypes.TimeUnresolvable(defsecTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Active:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
					Metadata:   defsecTypes.NewTestMetadata(),
					Name:       defsecTypes.String("loadbalafncer", defsecTypes.NewTestMetadata()),
					LastAccess: defsecTypes.TimeUnresolvable(defsecTypes.NewTestMetadata()),
					Policies:   nil,
					AccessKeys: []iam.AccessKey{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Active:   defsecTypes.BoolDefault(true, defsecTypes.NewTestMetadata()),
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
