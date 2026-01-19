package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/storage"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
						Name:                           iacTypes.StringTest("image-store.com"),
						Location:                       iacTypes.StringTest("EU"),
						EnableUniformBucketLevelAccess: iacTypes.BoolTest(true),
						Bindings: []iam.Binding{
							{
								Members: []iacTypes.StringValue{
									iacTypes.StringTest("group:test@example.com"),
								},
								Role: iacTypes.StringTest("roles/storage.admin #1"),
							},
						},
						Members: []iam.Member{
							{
								Member: iacTypes.StringTest("serviceAccount:test@example.com"),
								Role:   iacTypes.StringTest("roles/storage.admin #2"),
							},
						},
						Encryption: storage.BucketEncryption{
							DefaultKMSKeyName: iacTypes.StringTest("default-kms-key-name"),
						},
						Logging:    storage.BucketLogging{},
						Versioning: storage.BucketVersioning{},
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
						Bindings: []iam.Binding{
							{},
						},
						Members: []iam.Member{
							{},
						},
						Encryption: storage.BucketEncryption{},
						Logging:    storage.BucketLogging{},
						Versioning: storage.BucketVersioning{},
					},
				},
			},
		},
		{
			name: "with logging and versioning",
			terraform: `
			resource "google_storage_bucket" "example" {
			  name     = "example-bucket"
			  location = "US"

			  logging {
			    log_bucket = "access-logs-bucket"
			  }

			  versioning {
			    enabled = true
			  }
			}`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Name:       iacTypes.StringTest("example-bucket"),
						Location:   iacTypes.StringTest("US"),
						Encryption: storage.BucketEncryption{},
						Logging: storage.BucketLogging{
							LogBucket: iacTypes.StringTest("access-logs-bucket"),
						},
						Versioning: storage.BucketVersioning{
							Enabled: iacTypes.BoolTest(true),
						},
					},
				},
			},
		},
		{
			name: "with logging including log object prefix",
			terraform: `
			resource "google_storage_bucket" "example" {
			  name     = "example-bucket"
			  location = "US"

			  logging {
			    log_bucket = "access-logs-bucket"
			    log_object_prefix = "access-logs/"
			  }
			}`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Name:       iacTypes.StringTest("example-bucket"),
						Location:   iacTypes.StringTest("US"),
						Encryption: storage.BucketEncryption{},
						Logging: storage.BucketLogging{
							LogBucket:       iacTypes.StringTest("access-logs-bucket"),
							LogObjectPrefix: iacTypes.StringTest("access-logs/"),
						},
						Versioning: storage.BucketVersioning{},
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
