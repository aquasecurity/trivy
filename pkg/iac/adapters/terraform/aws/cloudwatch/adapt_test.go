package cloudwatch

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptLogGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []cloudwatch.LogGroup
	}{
		{
			name: "key referencing block",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				kms_key_id = aws_kms_key.log_key.arn
			}

			resource "aws_kms_key" "log_key" {
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        iacTypes.NewTestMetadata(),
					Arn:             iacTypes.String("", iacTypes.NewTestMetadata()),
					Name:            iacTypes.String("my-group", iacTypes.NewTestMetadata()),
					KMSKeyID:        iacTypes.String("aws_kms_key.log_key", iacTypes.NewTestMetadata()),
					RetentionInDays: iacTypes.Int(0, iacTypes.NewTestMetadata()),
					MetricFilters:   nil,
				},
			},
		},
		{
			name: "key as string",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				kms_key_id = "key-as-string"
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        iacTypes.NewTestMetadata(),
					Arn:             iacTypes.String("", iacTypes.NewTestMetadata()),
					Name:            iacTypes.String("my-group", iacTypes.NewTestMetadata()),
					KMSKeyID:        iacTypes.String("key-as-string", iacTypes.NewTestMetadata()),
					RetentionInDays: iacTypes.Int(0, iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "missing key",
			terraform: `
			resource "aws_cloudwatch_log_group" "my-group" {
				name = "my-group"
				retention_in_days = 3
			}
`,
			expected: []cloudwatch.LogGroup{
				{
					Metadata:        iacTypes.NewTestMetadata(),
					Arn:             iacTypes.String("", iacTypes.NewTestMetadata()),
					Name:            iacTypes.String("my-group", iacTypes.NewTestMetadata()),
					KMSKeyID:        iacTypes.String("", iacTypes.NewTestMetadata()),
					RetentionInDays: iacTypes.Int(3, iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLogGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudwatch_log_group" "my-group" {
		name = "my-group"
		kms_key_id = aws_kms_key.log_key.arn
		retention_in_days = 3

	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)
	require.Len(t, adapted.LogGroups, 1)
	logGroup := adapted.LogGroups[0]

	assert.Equal(t, 3, logGroup.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, logGroup.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, logGroup.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, logGroup.KMSKeyID.GetMetadata().Range().GetStartLine())

	assert.Equal(t, 5, logGroup.RetentionInDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, logGroup.RetentionInDays.GetMetadata().Range().GetStartLine())
}
