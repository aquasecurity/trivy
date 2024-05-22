package athena

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/athena"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptDatabase(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Database
	}{
		{
			name: "athena database",
			terraform: `
			resource "aws_athena_database" "my_wg" {
				name   = "database_name"
			  
				encryption_configuration {
				   encryption_option = "SSE_KMS"
			   }
			}
`,
			expected: athena.Database{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.String("database_name", iacTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: iacTypes.NewTestMetadata(),
					Type:     iacTypes.String(athena.EncryptionTypeSSEKMS, iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDatabase(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkgroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Workgroup
	}{
		{
			name: "encryption type SSE KMS",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = true
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			  }
`,
			expected: athena.Workgroup{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.String("example", iacTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: iacTypes.NewTestMetadata(),
					Type:     iacTypes.String(athena.EncryptionTypeSSEKMS, iacTypes.NewTestMetadata()),
				},
				EnforceConfiguration: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "configuration not enforced",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = false
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.String("example", iacTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: iacTypes.NewTestMetadata(),
					Type:     iacTypes.String(athena.EncryptionTypeSSEKMS, iacTypes.NewTestMetadata()),
				},
				EnforceConfiguration: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "enforce configuration defaults to true",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
					result_configuration {
						encryption_configuration {
						  encryption_option = ""
						}
					}
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.String("example", iacTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: iacTypes.NewTestMetadata(),
					Type:     iacTypes.String(athena.EncryptionTypeNone, iacTypes.NewTestMetadata()),
				},
				EnforceConfiguration: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "missing configuration block",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			}
`,
			expected: athena.Workgroup{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.String("example", iacTypes.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: iacTypes.NewTestMetadata(),
					Type:     iacTypes.String(athena.EncryptionTypeNone, iacTypes.NewTestMetadata()),
				},
				EnforceConfiguration: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkgroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_athena_database" "good_example" {
		name   = "database_name"
		bucket = aws_s3_bucket.hoge.bucket
	  
		encryption_configuration {
		   encryption_option = "SSE_KMS"
		   kms_key_arn       = aws_kms_key.example.arn
	   }
	  }
	  
	  resource "aws_athena_workgroup" "good_example" {
		name = "example"
	  
		configuration {
		  enforce_workgroup_configuration    = true
		  publish_cloudwatch_metrics_enabled = true
	  
		  result_configuration {
			output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
	  
			encryption_configuration {
			  encryption_option = "SSE_KMS"
			  kms_key_arn       = aws_kms_key.example.arn
			}
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Databases, 1)
	require.Len(t, adapted.Workgroups, 1)

	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetEndLine())
}
