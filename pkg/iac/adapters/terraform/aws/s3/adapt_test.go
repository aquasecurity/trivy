package s3

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/liamg/iamgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PublicAccessBlock(t *testing.T) {
	testCases := []struct {
		desc            string
		source          string
		expectedBuckets int
		hasPublicAccess bool
	}{
		{
			desc: "public access block is found when using the bucket name as the lookup",
			source: `
resource "aws_s3_bucket" "example" {
	bucket = "bucketname"
}

resource "aws_s3_bucket_public_access_block" "example_access_block"{
	bucket = "bucketname"
}
`,
			expectedBuckets: 1,
			hasPublicAccess: true,
		},
		{
			desc: "public access block is found when using the bucket name as the lookup",
			source: `
resource "aws_s3_bucket" "example" {
	bucket = "bucketname"
}

resource "aws_s3_bucket_public_access_block" "example_access_block"{
	bucket = aws_s3_bucket.example.id
}
`,
			expectedBuckets: 1,
			hasPublicAccess: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

			modules := tftestutil.CreateModulesFromSource(t, tC.source, ".tf")
			s3Ctx := Adapt(modules)

			assert.Equal(t, tC.expectedBuckets, len(s3Ctx.Buckets))

			for _, bucket := range s3Ctx.Buckets {
				if tC.hasPublicAccess {
					assert.NotNil(t, bucket.PublicAccessBlock)
				} else {
					assert.Nil(t, bucket.PublicAccessBlock)
				}
			}

			bucket := s3Ctx.Buckets[0]
			assert.NotNil(t, bucket.PublicAccessBlock)

		})
	}

}

func Test_PublicAccessDoesNotReference(t *testing.T) {
	testCases := []struct {
		desc   string
		source string
	}{
		{
			desc: "just a bucket, no public access block",
			source: `
resource "aws_s3_bucket" "example" {
	bucket = "bucketname"
}
			`,
		},
		{
			desc: "bucket with unrelated public access block",
			source: `
resource "aws_s3_bucket" "example" {
	bucket = "bucketname"
}

resource "aws_s3_bucket_public_access_block" "example_access_block"{
	bucket = aws_s3_bucket.other.id
}
			`,
		},
		{
			desc: "bucket with unrelated public access block via name",
			source: `
resource "aws_s3_bucket" "example" {
	bucket = "bucketname"
}

resource "aws_s3_bucket_public_access_block" "example_access_block"{
	bucket = "something"
}
			`,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, tC.source, ".tf")
			s3Ctx := Adapt(modules)
			require.Len(t, s3Ctx.Buckets, 1)
			assert.Nil(t, s3Ctx.Buckets[0].PublicAccessBlock)

		})
	}
}

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  s3.S3
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_s3_bucket" "example" {
				bucket = "bucket"
			}
			
			resource "aws_s3_bucket_public_access_block" "example" {
				 bucket = aws_s3_bucket.example.id
			   
				 restrict_public_buckets = true
				 block_public_acls   = true
				 block_public_policy = true
				 ignore_public_acls = true

			 }

			 resource "aws_s3_bucket_acl" "example" {
				bucket = aws_s3_bucket.example.id
				acl    = "private"
			  }

			  resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
				bucket = aws_s3_bucket.example.bucket
			  
				rule {
				  apply_server_side_encryption_by_default {
					kms_master_key_id = "string-key"
					sse_algorithm     = "aws:kms"
				  }
				}
			  }

			  resource "aws_s3_bucket_logging" "example" {
				bucket = aws_s3_bucket.example.id
			  
				target_bucket = aws_s3_bucket.example.id
				target_prefix = "log/"
			  }

			  resource "aws_s3_bucket_versioning" "versioning_example" {
				bucket = aws_s3_bucket.example.id
				versioning_configuration {
				  status = "Enabled"
                  mfa_delete = "Enabled"
				}
			  }

			  resource "aws_s3_bucket_policy" "allow_access_from_another_account" {
				bucket = aws_s3_bucket.example.bucket
				policy = data.aws_iam_policy_document.allow_access_from_another_account.json
			  }
			  
			  data "aws_iam_policy_document" "allow_access_from_another_account" {
				statement {
			  
				  actions = [
					"s3:GetObject",
					"s3:ListBucket",
				  ]
			  
				  resources = [
					"arn:aws:s3:::*",
				  ]
				}
			  }
		`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Name:     iacTypes.String("bucket", iacTypes.NewTestMetadata()),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:              iacTypes.NewTestMetadata(),
							BlockPublicACLs:       iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							BlockPublicPolicy:     iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							IgnorePublicACLs:      iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							RestrictPublicBuckets: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
						BucketPolicies: []iam.Policy{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Name:     iacTypes.String("", iacTypes.NewTestMetadata()),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"s3:GetObject", "s3:ListBucket"})
									sb.WithResources([]string{"arn:aws:s3:::*"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed:   builder.Build(),
										Metadata: iacTypes.NewTestMetadata(),
										IsOffset: true,
										HasRefs:  false,
									}
								}(),
								Builtin: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
							},
						},
						Encryption: s3.Encryption{
							Metadata:  iacTypes.NewTestMetadata(),
							Enabled:   iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							Algorithm: iacTypes.String("aws:kms", iacTypes.NewTestMetadata()),
							KMSKeyId:  iacTypes.String("string-key", iacTypes.NewTestMetadata()),
						},
						Versioning: s3.Versioning{
							Metadata:  iacTypes.NewTestMetadata(),
							Enabled:   iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							MFADelete: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
						},
						Logging: s3.Logging{
							Metadata:     iacTypes.NewTestMetadata(),
							Enabled:      iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							TargetBucket: iacTypes.String("aws_s3_bucket.example", iacTypes.NewTestMetadata()),
						},
						ACL: iacTypes.String("private", iacTypes.NewTestMetadata()),
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
		resource "aws_s3_bucket" "example" {
			bucket = "bucket"
		}

		resource "aws_s3_bucket_public_access_block" "example" {
			bucket = aws_s3_bucket.example.id
		
			restrict_public_buckets = true
			block_public_acls   = true
			block_public_policy = true
			ignore_public_acls = true
		}

		resource "aws_s3_bucket_acl" "example" {
			bucket = aws_s3_bucket.example.id
			acl    = "private"
		}

		resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
			bucket = aws_s3_bucket.example.bucket
		
			rule {
			apply_server_side_encryption_by_default {
				kms_master_key_id = "string-key"
				sse_algorithm     = "aws:kms"
			}
			}
		}

		resource "aws_s3_bucket_logging" "example" {
			bucket = aws_s3_bucket.example.id
		
			target_bucket = aws_s3_bucket.example.id
			target_prefix = "log/"
		}

		resource "aws_s3_bucket_versioning" "versioning_example" {
			bucket = aws_s3_bucket.example.id
			versioning_configuration {
			status = "Enabled"
			}
		}

		resource "aws_s3_bucket_policy" "allow_access_from_another_account" {
			bucket = aws_s3_bucket.example.bucket
			policy = data.aws_iam_policy_document.allow_access_from_another_account.json
		}
		
		data "aws_iam_policy_document" "allow_access_from_another_account" {
			statement {
		
			actions = [
				"s3:GetObject",
				"s3:ListBucket",
			]
		
			resources = [
				"arn:aws:s3:::*",
			]
			}
		}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	bucket := adapted.Buckets[0]

	assert.Equal(t, 2, bucket.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, bucket.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, bucket.PublicAccessBlock.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, bucket.PublicAccessBlock.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, bucket.PublicAccessBlock.RestrictPublicBuckets.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, bucket.PublicAccessBlock.RestrictPublicBuckets.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, bucket.PublicAccessBlock.BlockPublicACLs.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, bucket.PublicAccessBlock.BlockPublicACLs.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, bucket.PublicAccessBlock.BlockPublicPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, bucket.PublicAccessBlock.BlockPublicPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, bucket.PublicAccessBlock.IgnorePublicACLs.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, bucket.PublicAccessBlock.IgnorePublicACLs.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, bucket.ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, bucket.ACL.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, bucket.Encryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 29, bucket.Encryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 25, bucket.Encryption.KMSKeyId.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, bucket.Encryption.KMSKeyId.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, bucket.Encryption.Algorithm.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, bucket.Encryption.Algorithm.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 31, bucket.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 36, bucket.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 34, bucket.Logging.TargetBucket.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, bucket.Logging.TargetBucket.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, bucket.Versioning.Metadata.Range().GetStartLine())
	assert.Equal(t, 43, bucket.Versioning.Metadata.Range().GetEndLine())

	assert.Equal(t, 41, bucket.Versioning.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, bucket.Versioning.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 47, bucket.BucketPolicies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 47, bucket.BucketPolicies[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 50, bucket.BucketPolicies[0].Document.Metadata.Range().GetStartLine())
	assert.Equal(t, 62, bucket.BucketPolicies[0].Document.Metadata.Range().GetEndLine())
}
