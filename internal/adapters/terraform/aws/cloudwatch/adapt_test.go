package cloudwatch

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
					Metadata:        defsecTypes.NewTestMetadata(),
					Arn:             defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Name:            defsecTypes.String("my-group", defsecTypes.NewTestMetadata()),
					KMSKeyID:        defsecTypes.String("aws_kms_key.log_key", defsecTypes.NewTestMetadata()),
					RetentionInDays: defsecTypes.Int(0, defsecTypes.NewTestMetadata()),
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
					Metadata:        defsecTypes.NewTestMetadata(),
					Arn:             defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Name:            defsecTypes.String("my-group", defsecTypes.NewTestMetadata()),
					KMSKeyID:        defsecTypes.String("key-as-string", defsecTypes.NewTestMetadata()),
					RetentionInDays: defsecTypes.Int(0, defsecTypes.NewTestMetadata()),
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
					Metadata:        defsecTypes.NewTestMetadata(),
					Arn:             defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Name:            defsecTypes.String("my-group", defsecTypes.NewTestMetadata()),
					KMSKeyID:        defsecTypes.String("", defsecTypes.NewTestMetadata()),
					RetentionInDays: defsecTypes.Int(3, defsecTypes.NewTestMetadata()),
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
