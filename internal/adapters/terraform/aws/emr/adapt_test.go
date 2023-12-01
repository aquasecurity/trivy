package emr

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.StringExplicit("emrsc_test", defsecTypes.NewTestMetadata()),
				Configuration: defsecTypes.String(
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
`, defsecTypes.NewTestMetadata()),
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
