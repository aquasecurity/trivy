package compute

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("disk #1", iacTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   iacTypes.NewTestMetadata(),
						KMSKeyLink: iacTypes.String("something", iacTypes.NewTestMetadata()),
					},
				},
				{
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("disk #2", iacTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   iacTypes.NewTestMetadata(),
						KMSKeyLink: iacTypes.String("", iacTypes.NewTestMetadata()),
						RawKey:     iacTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), iacTypes.NewTestMetadata()),
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
					Metadata: iacTypes.NewTestMetadata(),
					Name:     iacTypes.String("disk #3", iacTypes.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   iacTypes.NewTestMetadata(),
						KMSKeyLink: iacTypes.String("google_kms_crypto_key.my_crypto_key", iacTypes.NewTestMetadata()),
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
