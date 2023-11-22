package storage

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/providers/google/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name: "defined",
			terraform: `
			resource "google_storage_bucket" "static-site" {
			  name                        = "image-store.com"
			  location                    = "EU"				
			  uniform_bucket_level_access = true

			  encryption {
			    default_kms_key_name = "default-kms-key-name"
			  }
			}

			resource "google_storage_bucket_iam_binding" "binding" {
			  bucket = google_storage_bucket.static-site.name
			  role   = "roles/storage.admin #1"
			  members = [
			    "group:test@example.com",
			  ]
			}

			resource "google_storage_bucket_iam_member" "example" {
			  member = "serviceAccount:test@example.com"
			  bucket = google_storage_bucket.static-site.name
			  role   = "roles/storage.admin #2"
			}`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       defsecTypes.NewTestMetadata(),
						Name:                           defsecTypes.String("image-store.com", defsecTypes.NewTestMetadata()),
						Location:                       defsecTypes.String("EU", defsecTypes.NewTestMetadata()),
						EnableUniformBucketLevelAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						Bindings: []iam.Binding{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []defsecTypes.StringValue{
									defsecTypes.String("group:test@example.com", defsecTypes.NewTestMetadata()),
								},
								Role:                          defsecTypes.String("roles/storage.admin #1", defsecTypes.NewTestMetadata()),
								IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
						Members: []iam.Member{
							{
								Metadata:              defsecTypes.NewTestMetadata(),
								Member:                defsecTypes.String("serviceAccount:test@example.com", defsecTypes.NewTestMetadata()),
								Role:                  defsecTypes.String("roles/storage.admin #2", defsecTypes.NewTestMetadata()),
								DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
						Encryption: storage.BucketEncryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							DefaultKMSKeyName: defsecTypes.String("default-kms-key-name", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_storage_bucket" "static-site" {	
			}

			resource "google_storage_bucket_iam_binding" "binding" {
			  bucket = google_storage_bucket.static-site.name
			}

			resource "google_storage_bucket_iam_member" "example" {
			  bucket = google_storage_bucket.static-site.name
			}`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       defsecTypes.NewTestMetadata(),
						Name:                           defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Location:                       defsecTypes.String("", defsecTypes.NewTestMetadata()),
						EnableUniformBucketLevelAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						Bindings: []iam.Binding{
							{
								Metadata:                      defsecTypes.NewTestMetadata(),
								Role:                          defsecTypes.String("", defsecTypes.NewTestMetadata()),
								IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
						Members: []iam.Member{
							{
								Metadata:              defsecTypes.NewTestMetadata(),
								Member:                defsecTypes.String("", defsecTypes.NewTestMetadata()),
								Role:                  defsecTypes.String("", defsecTypes.NewTestMetadata()),
								DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
						Encryption: storage.BucketEncryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							DefaultKMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
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
	resource "google_storage_bucket" "static-site" {
	  name                        = "image-store.com"
	  location                    = "EU"				
	  uniform_bucket_level_access = true
	}

	resource "google_storage_bucket_iam_binding" "binding" {
	  bucket = google_storage_bucket.static-site.name
	  role   = "roles/storage.admin #1"
	  members = [
	    "group:test@example.com",
	  ]
	}

	resource "google_storage_bucket_iam_member" "example" {
	  member = "serviceAccount:test@example.com"
	  bucket = google_storage_bucket.static-site.name
	  role   = "roles/storage.admin #2"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	require.Len(t, adapted.Buckets[0].Bindings, 1)
	require.Len(t, adapted.Buckets[0].Members, 1)

	bucket := adapted.Buckets[0]
	binding := adapted.Buckets[0].Bindings[0]
	member := adapted.Buckets[0].Members[0]

	assert.Equal(t, 2, bucket.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, bucket.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, bucket.Location.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, bucket.Location.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, bucket.EnableUniformBucketLevelAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, bucket.EnableUniformBucketLevelAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, binding.Metadata.Range().GetStartLine())
	assert.Equal(t, 14, binding.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, binding.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, binding.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, binding.Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, binding.Members[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, member.Metadata.Range().GetStartLine())
	assert.Equal(t, 20, member.Metadata.Range().GetEndLine())

	assert.Equal(t, 17, member.Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, member.Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, member.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, member.Role.GetMetadata().Range().GetEndLine())
}
