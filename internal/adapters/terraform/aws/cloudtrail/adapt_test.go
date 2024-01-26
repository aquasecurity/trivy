package cloudtrail

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTrail(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudtrail.Trail
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_cloudtrail" "example" {
				name = "example"
				is_multi_region_trail = true
			  
				enable_log_file_validation = true
				kms_key_id = "kms-key"
				s3_bucket_name = "abcdefgh"
				cloud_watch_logs_group_arn = "abc"
				enable_logging = false
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                  defsecTypes.NewTestMetadata(),
				Name:                      defsecTypes.String("example", defsecTypes.NewTestMetadata()),
				EnableLogFileValidation:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				IsMultiRegion:             defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				KMSKeyID:                  defsecTypes.String("kms-key", defsecTypes.NewTestMetadata()),
				CloudWatchLogsLogGroupArn: defsecTypes.String("abc", defsecTypes.NewTestMetadata()),
				IsLogging:                 defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				BucketName:                defsecTypes.String("abcdefgh", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_cloudtrail" "example" {
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                  defsecTypes.NewTestMetadata(),
				Name:                      defsecTypes.String("", defsecTypes.NewTestMetadata()),
				EnableLogFileValidation:   defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				IsMultiRegion:             defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				KMSKeyID:                  defsecTypes.String("", defsecTypes.NewTestMetadata()),
				BucketName:                defsecTypes.String("", defsecTypes.NewTestMetadata()),
				CloudWatchLogsLogGroupArn: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				IsLogging:                 defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTrail(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudtrail" "example" {
		name = "example"
		is_multi_region_trail = true
	  
		enable_log_file_validation = true
		kms_key_id = "kms-key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Trails, 1)
	trail := adapted.Trails[0]

	assert.Equal(t, 2, trail.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, trail.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetEndLine())
}
