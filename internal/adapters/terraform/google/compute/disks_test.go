package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/google/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_adaptDisks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Disk
	}{
		{
			name: "key as string link or raw bytes",
			terraform: `
			resource "google_compute_disk" "example-one" {
				name  = "disk #1"
			
				disk_encryption_key {
				  kms_key_self_link = "something"
				}
			  }

			  resource "google_compute_disk" "example-two" {
				name  = "disk #2"
			
				disk_encryption_key {
				  raw_key="b2ggbm8gdGhpcyBpcyBiYWQ"
				}
			  }
`,
			expected: []compute.Disk{
				{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("disk #1", defsecTypes.NewTestMisconfigMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   defsecTypes.NewTestMisconfigMetadata(),
						KMSKeyLink: defsecTypes.String("something", defsecTypes.NewTestMisconfigMetadata()),
					},
				},
				{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("disk #2", defsecTypes.NewTestMisconfigMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   defsecTypes.NewTestMisconfigMetadata(),
						KMSKeyLink: defsecTypes.String("", defsecTypes.NewTestMisconfigMetadata()),
						RawKey:     defsecTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), defsecTypes.NewTestMisconfigMetadata()),
					},
				},
			},
		},
		{
			name: "key link as reference",
			terraform: `
			resource "google_kms_crypto_key" "my_crypto_key" {
				name            = "crypto-key-example"
			  }

			resource "google_compute_disk" "example-three" {
				name  = "disk #3"
			
				disk_encryption_key {
					kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
				}
			  }`,
			expected: []compute.Disk{
				{
					Metadata: defsecTypes.NewTestMisconfigMetadata(),
					Name:     defsecTypes.String("disk #3", defsecTypes.NewTestMisconfigMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   defsecTypes.NewTestMisconfigMetadata(),
						KMSKeyLink: defsecTypes.String("google_kms_crypto_key.my_crypto_key", defsecTypes.NewTestMisconfigMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDisks(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
