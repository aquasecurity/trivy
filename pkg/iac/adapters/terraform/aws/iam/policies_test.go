package iam

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/liamg/iamgo"
)

func defaultPolicyDocuemnt(offset bool) iam.Document {

	builder := iamgo.NewPolicyBuilder()
	builder.WithVersion("2012-10-17")

	sb := iamgo.NewStatementBuilder()
	sb.WithEffect(iamgo.EffectAllow)
	sb.WithActions([]string{"ec2:Describe*"})
	sb.WithResources([]string{"*"})

	builder.WithStatement(sb.Build())

	return iam.Document{
		Parsed:   builder.Build(),
		Metadata: iacTypes.NewTestMetadata(),
		IsOffset: offset,
		HasRefs:  false,
	}
}

func Test_adaptPolicies(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Policy
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_policy" "policy" {
				name = "test"	

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
			expected: []iam.Policy{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test", iacTypes.NewTestMetadata()),
					Document: defaultPolicyDocuemnt(false),
					Builtin:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "aws_iam_policy_document with count Meta-Argument",
			terraform: `locals {
  sqs = [
    "arn:aws:sqs:::*"
  ]
}

data "aws_iam_policy_document" "this" {
  count = length(local.sqs)
  statement {
    sid = "test-${count.index}"
    actions = [
      "sqs:CancelMessageMoveTask"
    ]
    resources = [
      "${local.sqs[count.index]}"
    ]
  }
}

resource "aws_iam_policy" "this" {
  count  = length(local.sqs)
  name   = "test-${count.index}"
  policy = data.aws_iam_policy_document.this[count.index].json
}
`,
			expected: []iam.Policy{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-0", iacTypes.NewTestMetadata()),
					Builtin:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Document: iam.Document{
						Metadata: iacTypes.NewTestMetadata(),
						IsOffset: true,
						HasRefs:  false,
						Parsed: func() iamgo.Document {
							builder := iamgo.NewPolicyBuilder()

							sb := iamgo.NewStatementBuilder()
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithSid("test-0")
							sb.WithActions([]string{"sqs:CancelMessageMoveTask"})
							sb.WithResources([]string{"arn:aws:sqs:::*"})

							builder.WithStatement(sb.Build())
							return builder.Build()
						}(),
					},
				},
			},
		},
		{
			name: "aws_iam_policy_document with for_each meta-argument",
			terraform: `locals {
  sqs = {
    sqs1 = "arn:aws:sqs:::*"
  }
}

data "aws_iam_policy_document" "this" {
  for_each = local.sqs

  statement {
    sid = each.key
    actions = [
      "sqs:CancelMessageMoveTask"
    ]
    resources = [each.value]
  }
}

resource "aws_iam_policy" "this" {
  for_each = local.sqs
  name     = "test-${each.key}"
  policy   = data.aws_iam_policy_document.this[each.key].json
}`,
			expected: []iam.Policy{
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("test-sqs1", iacTypes.NewTestMetadata()),
					Builtin:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Document: iam.Document{
						Metadata: iacTypes.NewTestMetadata(),
						IsOffset: true,
						HasRefs:  false,
						Parsed: func() iamgo.Document {
							builder := iamgo.NewPolicyBuilder()

							sb := iamgo.NewStatementBuilder()
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithSid("sqs1")
							sb.WithActions([]string{"sqs:CancelMessageMoveTask"})
							sb.WithResources([]string{"arn:aws:sqs:::*"})

							builder.WithStatement(sb.Build())
							return builder.Build()
						}(),
					},
				},
			},
		},
		{
			name: "policy_document with source_policy_documents",
			terraform: `
data "aws_iam_policy_document" "source" {
  statement {
    actions   = ["ec2:*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "source_document_example" {
  source_policy_documents = [data.aws_iam_policy_document.source.json]

  statement {
    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::somebucket",
      "arn:aws:s3:::somebucket/*",
    ]
  }
}

resource "aws_iam_policy" "this" {
  name   = "test-policy"
  policy = data.aws_iam_policy_document.source_document_example.json
}`,
			expected: []iam.Policy{
				{
					Name:    iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
					Builtin: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Document: func() iam.Document {
						builder := iamgo.NewPolicyBuilder()
						firstStatement := iamgo.NewStatementBuilder().
							WithActions([]string{"ec2:*"}).
							WithResources([]string{"*"}).
							WithEffect("Allow").
							Build()

						builder.WithStatement(firstStatement)

						secondStatement := iamgo.NewStatementBuilder().
							WithActions([]string{"s3:*"}).
							WithResources([]string{"arn:aws:s3:::somebucket", "arn:aws:s3:::somebucket/*"}).
							WithEffect("Allow").
							Build()

						builder.WithStatement(secondStatement)

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
		{
			name: "source_policy_documents with for-each",
			terraform: `
locals {
  versions = ["2008-10-17", "2012-10-17"]
}

resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  source_policy_documents = [for s in data.aws_iam_policy_document.policy_source : s.json if s.version != "2008-10-17"]
  statement {
    actions   = ["s3:*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "policy_source" {
  for_each = toset(local.versions)
  version  = each.value
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}`,
			expected: []iam.Policy{
				{
					Name: iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
					Document: func() iam.Document {
						builder := iamgo.NewPolicyBuilder().
							WithStatement(
								iamgo.NewStatementBuilder().
									WithActions([]string{"s3:PutObject"}).
									WithResources([]string{"*"}).
									WithEffect("Allow").
									Build(),
							).
							WithStatement(
								iamgo.NewStatementBuilder().
									WithActions([]string{"s3:*"}).
									WithResources([]string{"*"}).
									WithEffect("Allow").
									Build(),
							)

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
		{
			name: "source_policy_documents with condition",
			terraform: `
locals {
  versions = ["2008-10-17", "2012-10-17"]
}

resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  source_policy_documents = true ? [data.aws_iam_policy_document.policy_source.json] : [data.aws_iam_policy_document.policy_source2.json]
}

data "aws_iam_policy_document" "policy_source" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "policy_source2" {
  statement {
    actions   = ["s3:PutObject2"]
    resources = ["*"]
  }
}
`,
			expected: []iam.Policy{
				{
					Name: iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
					Document: func() iam.Document {
						builder := iamgo.NewPolicyBuilder().
							WithStatement(
								iamgo.NewStatementBuilder().
									WithActions([]string{"s3:PutObject"}).
									WithResources([]string{"*"}).
									WithEffect("Allow").
									Build(),
							)

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
		{
			name: "raw source policy",
			terraform: `resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  source_policy_documents = [
    jsonencode({
      Statement = [
        {
          Action = [
            "ec2:Describe*",
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    }),
  ]
}
`,
			expected: []iam.Policy{
				{
					Name: iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
					Document: func() iam.Document {
						builder := iamgo.NewPolicyBuilder().
							WithStatement(
								iamgo.NewStatementBuilder().
									WithActions([]string{"ec2:Describe*"}).
									WithResources([]string{"*"}).
									WithEffect("Allow").
									Build(),
							)

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
		{
			name: "invalid `override_policy_documents` attribute",
			terraform: `resource "aws_iam_policy" "test_policy" {
  name   = "test-policy"
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  source_policy_documents = data.aws_iam_policy_document.policy2.json
}`,
			expected: []iam.Policy{
				{
					Name: iacTypes.String("test-policy", iacTypes.NewTestMetadata()),
					Document: iam.Document{
						IsOffset: true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
