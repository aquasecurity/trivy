package sqs

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/liamg/iamgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sqs.SQS
	}{
		{
			name: "np kms key",
			terraform: `
			resource "aws_sqs_queue" "good_example" {

				policy = <<POLICY
				{
				  "Statement": [
					{
					  "Effect": "Allow",
					  "Action": "*"
					}
				  ]
				}
				POLICY
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						QueueURL: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							ManagedEncryption: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							KMSKeyID:          defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
						Policies: func() []iam.Policy {
							sb := iamgo.NewStatementBuilder()
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"*",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									Name:     defsecTypes.StringDefault("", defsecTypes.NewTestMetadata()),
									Document: iam.Document{
										Metadata: defsecTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
									Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								},
							}
						}(),
					},
				},
			},
		},
		{
			name: "no policy",
			terraform: `
			resource "aws_sqs_queue" "good_example" {
				kms_master_key_id = "/blah"
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						QueueURL: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							ManagedEncryption: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							KMSKeyID:          defsecTypes.String("/blah", defsecTypes.NewTestMetadata()),
						},
						Policies: nil,
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

func TestLines(t *testing.T) {
	src := `
	resource "aws_sqs_queue" "good_example" {
		kms_master_key_id = "key"

		policy = <<POLICY
		{
		  "Statement": [
			{
			  "Effect": "Allow",
			  "Action": "*"
			}
		  ]
		}
		POLICY
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Queues, 1)
	queue := adapted.Queues[0]

	assert.Equal(t, 2, queue.Metadata.Range().GetStartLine())
	assert.Equal(t, 15, queue.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, queue.Policies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 14, queue.Policies[0].Metadata.Range().GetEndLine())
}
