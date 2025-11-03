package iam

import (
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/iamgo"
	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
		{
			name: "attach AWS managed policy using ARN directly",
			terraform: `resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}`,
			expected: []iam.Role{
				{
					Name: iacTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
		{
			name: "attach AWS managed policy using ARN from data source",
			terraform: `data "aws_iam_policy" "s3_full_access" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = data.aws_iam_policy.s3_full_access.arn
}`,
			expected: []iam.Role{
				{
					Name: iacTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
		{
			name: "attach AWS managed policy using data source with policy name",
			terraform: `data "aws_iam_policy" "s3_full_access" {
  name = "AmazonS3FullAccess"
}

resource "aws_iam_role" "test" {
  name = "example-role"
}

resource "aws_iam_role_policy_attachment" "test" {
  role       = aws_iam_role.test.name
  policy_arn = data.aws_iam_policy.s3_full_access.arn
}`,
			expected: []iam.Role{
				{
					Name: iacTypes.StringTest("example-role"),
					Policies: []iam.Policy{
						{
							Name: iacTypes.StringTest("AmazonS3FullAccess"),
							Document: iam.Document{
								Parsed: s3FullAccessPolicyDocument,
							},
						},
					},
				},
			},
		},
		{
			name: "policy is template with unknown part",
			terraform: `resource "aws_iam_role" "default" {
  name = "test"
}

resource "aws_iam_role_policy_attachment" "amazon_eks_cluster_policy" {
  role       = aws_iam_role.default.name
  policy_arn = format("arn:%s:iam::aws:policy/AmazonEKSClusterPolicy", data.aws_partition.current.partition)
}


data "aws_partition" "current" {}
`,
			expected: []iam.Role{
				{
					Name: iacTypes.StringTest("test"),
					Policies: []iam.Policy{
						{
							Name:     iacTypes.StringTest(""),
							Document: iam.Document{},
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

// validateLambdaEcsKeys validates that attachment references contain both lambda and ecs-tasks keys
func validateLambdaEcsKeys(t *testing.T, attachmentRefs []string) {
	hasLambda := false
	hasEcs := false
	for _, ref := range attachmentRefs {
		if strings.Contains(ref, "lambda") {
			hasLambda = true
		}
		if strings.Contains(ref, "ecs-tasks") {
			hasEcs = true
		}
	}
	if !hasLambda || !hasEcs {
		t.Errorf("expected attachment refs to include both lambda and ecs-tasks keys, got %v", attachmentRefs)
	}
}

func Test_forEachReferences(t *testing.T) {
	tests := []struct {
		name          string
		terraform     string
		expectedCount int
	}{
		{
			name: "computed local with for_each map",
			terraform: `
locals {
  platform_role_principals = {
    lambda    = "lambda.amazonaws.com"
    ecs-tasks = "ecs-tasks.amazonaws.com"
  }
}

data "aws_iam_policy_document" "platform_role_assume_policy" {
  for_each = local.platform_role_principals

  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [each.value]
    }
  }
}

resource "aws_iam_role" "platform_role" {
  for_each           = local.platform_role_principals
  name               = "platform-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.platform_role_assume_policy[each.key].json
}

locals {
  platform_roles = {
    for role_key, role_res in aws_iam_role.platform_role :
    role_key => {
      role = role_res.name
    }
  }
}

data "aws_iam_policy_document" "administrative_policy_doc" {
  statement {
    resources = ["*"]
    actions   = ["Tag:GetResources", "Tag:TagResources", "Tag:UntagResources"]
  }
}

resource "aws_iam_policy" "administrative_policy" {
  name   = "administrative-policy"
  policy = data.aws_iam_policy_document.administrative_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "administrative_policy_attachment" {
  for_each   = local.platform_roles
  role       = each.value.role
  policy_arn = aws_iam_policy.administrative_policy.arn
}`,
			expectedCount: 2,
		},
		{
			name: "direct for_each reference",
			terraform: `
locals {
  roles = {
    lambda    = "lambda.amazonaws.com"
    ecs-tasks = "ecs-tasks.amazonaws.com"
  }
}

resource "aws_iam_role" "platform_role" {
  for_each = local.roles
  name     = "platform-${each.key}"
}

resource "aws_iam_role_policy_attachment" "test" {
  for_each = aws_iam_role.platform_role
  role     = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}`,
			expectedCount: 2,
		},
		{
			name: "for_each with computed local reference",
			terraform: `
locals {
  role_principals = {
    lambda    = "lambda.amazonaws.com"
    ecs-tasks = "ecs-tasks.amazonaws.com"
  }
}

resource "aws_iam_role" "platform_role" {
  for_each = local.role_principals
  name     = "platform-${each.key}"
}

locals {
  platform_roles = {
    for role_key, role_res in aws_iam_role.platform_role :
    role_key => {
      role = role_res.name
    }
  }
}

resource "aws_iam_role_policy_attachment" "test" {
  for_each = local.platform_roles
  role     = each.value.role
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}`,
			expectedCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			attachments := modules.GetResourcesByType("aws_iam_role_policy_attachment")

			// Debug output for troubleshooting
			t.Logf("Total resources found: %d", len(attachments))
			for i, attachment := range attachments {
				t.Logf("Attachment %d: %s", i, attachment.Reference().String())
				t.Logf("  - FullName: %s", attachment.FullName())
				t.Logf("  - TypeLabel: %s", attachment.TypeLabel())
				t.Logf("  - NameLabel: %s", attachment.NameLabel())
				if key := attachment.Reference().RawKey(); !key.IsNull() && key.IsKnown() {
					t.Logf("  - Key: %s (%s)", key.GoString(), key.Type().GoString())
				}
			}

			var attachmentRefs []string
			for _, a := range attachments {
				attachmentRefs = append(attachmentRefs, a.Reference().String())
			}

			sort.Strings(attachmentRefs)

			if len(attachments) != test.expectedCount {
				t.Fatalf("expected %d policy attachments, got %d: %v", test.expectedCount, len(attachments), attachmentRefs)
			}

			// Validate that both lambda and ecs-tasks keys are present
			validateLambdaEcsKeys(t, attachmentRefs)
		})
	}
}
