package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
)

func Test_GetBuckets(t *testing.T) {

	source := `
resource "aws_s3_bucket" "bucket1" {

	
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)

}

func Test_BucketGetACL(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
  acl    = "authenticated-read"

  # ... other configuration ...
}`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.Equal(t, "authenticated-read", s3.Buckets[0].ACL.Value())

}

func Test_V4BucketGetACL(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "authenticated-read"
}`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.Equal(t, "authenticated-read", s3.Buckets[0].ACL.Value())

}

func Test_BucketGetLogging(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Logging.Enabled.Value())

}

func Test_V4BucketGetLogging(t *testing.T) {

	source := `
resource "aws_s3_bucket" "log_bucket" {
  bucket = "example-log-bucket"

  # ... other configuration ...
}

resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 2)
	for _, bucket := range s3.Buckets {
		switch bucket.Name.Value() {
		case "yournamehere":
			assert.True(t, bucket.Logging.Enabled.Value())
		case "example-log-bucket":
			assert.False(t, bucket.Logging.Enabled.Value())
		}
	}
}

func Test_BucketGetVersioning(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  versioning {
    enabled = true
  }
}`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())
}

func Test_V4BucketGetVersioning(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())
}

func Test_BucketGetVersioningWithLockDeprecated(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
  object_lock_configuration {
    object_lock_enabled = "Enabled"
  }
}	
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())

}

func Test_BucketGetVersioningWithLockForNewBucket(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "example" {
	bucket = aws_s3_bucket.example.id
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())

}

func Test_BucketGetVersioningWhenLockDisabledButVersioningEnabled(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
}

resource "aws_s3_bucket_object_lock_configuration" "example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())

}

func Test_BucketGetEncryption(t *testing.T) {

	source := `
	resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Encryption.Enabled.Value())
}

func Test_V4BucketGetEncryption(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Len(t, s3.Buckets, 1)
	assert.True(t, s3.Buckets[0].Encryption.Enabled.Value())
}

func Test_BucketWithPolicy(t *testing.T) {

	source := `
resource "aws_s3_bucket" "bucket1" {
	bucket = "lol"	
}

resource "aws_s3_bucket_policy" "allow_access_from_another_account" {
  bucket = aws_s3_bucket.bucket1.id
  policy = data.aws_iam_policy_document.allow_access_from_another_account.json
}

data "aws_iam_policy_document" "allow_access_from_another_account" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["123456789012"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.bucket1.arn,
    ]
  }
}

`
	modules := tftestutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	require.Len(t, s3.Buckets, 1)
	require.Len(t, s3.Buckets[0].BucketPolicies, 1)

	policy := s3.Buckets[0].BucketPolicies[0]

	statements, _ := policy.Document.Parsed.Statements()
	require.Len(t, statements, 1)

	principals, _ := statements[0].Principals()
	actions, _ := statements[0].Actions()

	awsPrincipals, _ := principals.AWS()
	require.Len(t, awsPrincipals, 1)
	require.Len(t, actions, 2)

}
