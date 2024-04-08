package iam

import (
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/liamg/iamgo"
)

func Test_adaptRoles(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Role
	}{
		{
			name: "policy",
			terraform: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id
  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "s3.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "policy" {
	version = "2012-10-17"
	statement {
	  effect    = "Allow"
	  actions   = ["ec2:Describe*"]
	  resources = ["*"]
	}
  }
`,
			expected: []iam.Role{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test_role", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test_policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "policy attachment",
			terraform: `
resource "aws_iam_role" "role" {
  name               = "test-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "policy" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.Role{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-role", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "inline policy",
			terraform: `
resource "aws_iam_role" "example" {
  name               = "test-role"
  
  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}
`,
			expected: []iam.Role{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-role", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("my_inline_policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
						},
					},
				},
			},
		},
		{
			name: "with for_each",
			terraform: `
locals {
  roles = toset(["test-role1", "test-role2"])
}

resource "aws_iam_role" "this" {
  for_each           = local.roles
  name               = each.key
  assume_role_policy = "{}"
}

data "aws_iam_policy_document" "this" {
  for_each = local.roles
  version  = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "this" {
  for_each    = local.roles
  name        = format("%s-policy", each.key)
  description = "A test policy"
  policy      = data.aws_iam_policy_document.this[each.key].json
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each   = local.roles
  role       = aws_iam_role.this[each.key].name
  policy_arn = aws_iam_policy.this[each.key].arn
}
`,
			expected: []iam.Role{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-role1", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test-role1-policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-role2", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: iacTypes.NewTestMetadata(),
							Name:     iacTypes.String("test-role2-policy", iacTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "policy with condition",
			terraform: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id
  policy = false ? data.aws_iam_policy_document.s3_policy.json : data.aws_iam_policy_document.s3_policy_one.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = ""
}

data "aws_iam_policy_document" "s3_policy_one" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:CreateBucket"]
    resources = ["*"]
  }
}`,
			expected: []iam.Role{
				{
					Name: iacTypes.String("test_role", iacTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Name:    iacTypes.String("test_policy", iacTypes.NewTestMetadata()),
							Builtin: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							Document: func() iam.Document {
								builder := iamgo.NewPolicyBuilder()
								sb := iamgo.NewStatementBuilder()
								sb.WithEffect(iamgo.EffectAllow)
								sb.WithActions([]string{"s3:PutObject"})
								sb.WithResources([]string{"*"})

								builder.WithStatement(sb.Build())

								return iam.Document{
									Parsed:   builder.Build(),
									Metadata: iacTypes.NewTestMetadata(),
									IsOffset: true,
									HasRefs:  false,
								}
							}(),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRoles(modules)
			sort.Slice(adapted, func(i, j int) bool {
				return adapted[i].Name.Value() < adapted[j].Name.Value()
			})
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
