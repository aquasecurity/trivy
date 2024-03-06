package s3

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/require"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected s3.S3
	}{
		{
			name: "complete s3 bucket",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Key:
    Type: "AWS::KMS::Key"
  LoggingBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: logging-bucket
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              KMSMasterKeyID:
                Fn::GetAtt:
                  - Key
                  - Arn
              SSEAlgorithm: aws:kms
      AccessControl: AwsExecRead
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LoggingConfiguration:
        DestinationBucketName: !Ref LoggingBucket
        LogFilePrefix: testing-logs
      LifecycleConfiguration:
        Rules:
          - Id: GlacierRule
            Prefix: glacier
            Status: Enabled
            ExpirationInDays: 365
      AccelerateConfiguration:
        AccelerationStatus: Enabled
`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.String("logging-bucket", types.NewTestMetadata()),
					},
					{
						Name: types.String("test-bucket", types.NewTestMetadata()),
						Encryption: s3.Encryption{
							Enabled:   types.Bool(true, types.NewTestMetadata()),
							Algorithm: types.String("aws:kms", types.NewTestMetadata()),
							KMSKeyId:  types.String("Key", types.NewTestMetadata()),
						},
						ACL: types.String("aws-exec-read", types.NewTestMetadata()),
						PublicAccessBlock: &s3.PublicAccessBlock{
							BlockPublicACLs:       types.Bool(true, types.NewTestMetadata()),
							BlockPublicPolicy:     types.Bool(true, types.NewTestMetadata()),
							IgnorePublicACLs:      types.Bool(true, types.NewTestMetadata()),
							RestrictPublicBuckets: types.Bool(true, types.NewTestMetadata()),
						},
						Logging: s3.Logging{
							TargetBucket: types.String("LoggingBucket", types.NewTestMetadata()),
							Enabled:      types.Bool(true, types.NewTestMetadata()),
						},
						LifecycleConfiguration: []s3.Rules{
							{
								Status: types.String("Enabled", types.NewTestMetadata()),
							},
						},
						AccelerateConfigurationStatus: types.String("Enabled", types.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "empty s3 bucket",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.String("test-bucket", types.NewTestMetadata()),
						Encryption: s3.Encryption{
							Enabled: types.BoolDefault(false, types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "incorrect SSE algorithm",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              KMSMasterKeyID: alias/my-key
              SSEAlgorithm: aes256
`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.String("test-bucket", types.NewTestMetadata()),
						Encryption: s3.Encryption{
							Enabled:   types.BoolDefault(false, types.NewTestMetadata()),
							KMSKeyId:  types.String("alias/my-key", types.NewTestMetadata()),
							Algorithm: types.String("aes256", types.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			fsys := testutil.CreateFS(t, map[string]string{
				"main.yaml": tt.source,
			})

			fctx, err := parser.New().ParseFile(context.TODO(), fsys, "main.yaml")
			require.NoError(t, err)

			adapted := Adapt(*fctx)
			testutil.AssertDefsecEqual(t, tt.expected, adapted)
		})
	}

}
