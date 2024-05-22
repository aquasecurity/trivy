package emr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/emr"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptSecurityConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  emr.SecurityConfiguration
	}{
		{
			name: "test",
			terraform: `
			resource "aws_emr_security_configuration" "foo" {
				name = "emrsc_test"
				configuration = <<EOF
				{
					"EncryptionConfiguration": {
					"AtRestEncryptionConfiguration": {
						"S3EncryptionConfiguration": {
						"EncryptionMode": "SSE-S3"
						},
						"LocalDiskEncryptionConfiguration": {
						"EncryptionKeyProviderType": "AwsKms",
						"AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
						}
					},
					"EnableInTransitEncryption": false,
					"EnableAtRestEncryption": true
					}
				}
				EOF
			}`,
			expected: emr.SecurityConfiguration{
				Metadata: iacTypes.NewTestMetadata(),
				Name:     iacTypes.StringExplicit("emrsc_test", iacTypes.NewTestMetadata()),
				Configuration: iacTypes.String(
					`				{
					"EncryptionConfiguration": {
					"AtRestEncryptionConfiguration": {
						"S3EncryptionConfiguration": {
						"EncryptionMode": "SSE-S3"
						},
						"LocalDiskEncryptionConfiguration": {
						"EncryptionKeyProviderType": "AwsKms",
						"AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
						}
					},
					"EnableInTransitEncryption": false,
					"EnableAtRestEncryption": true
					}
				}
`, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecurityConfiguration(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_emr_security_configuration" "foo" {
		name = "emrsc_other"
	  
		configuration = <<EOF
	  {
		"EncryptionConfiguration": {
		  "AtRestEncryptionConfiguration": {
			"S3EncryptionConfiguration": {
			  "EncryptionMode": "SSE-S3"
			},
			"LocalDiskEncryptionConfiguration": {
			  "EncryptionKeyProviderType": "AwsKms",
			  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
			}
		  },
		  "EnableInTransitEncryption": false,
		  "EnableAtRestEncryption": true
		}
	  }
	  EOF
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.SecurityConfiguration, 1)

	securityConfiguration := adapted.SecurityConfiguration[0]

	assert.Equal(t, 2, securityConfiguration.Metadata.Range().GetStartLine())
	assert.Equal(t, 22, securityConfiguration.Metadata.Range().GetEndLine())

	assert.Equal(t, 5, securityConfiguration.Configuration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, securityConfiguration.Configuration.GetMetadata().Range().GetEndLine())

	// assert.Equal(t, 2, securityConfiguration.Configuration.Contains("EncryptionConfiguration"))
}
