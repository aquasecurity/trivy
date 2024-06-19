package ecr

import (
	"testing"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ecr.ECR
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:

`,
			expected: ecr.ECR{},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyRepository: 
    Type: AWS::ECR::Repository
    Properties: 
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: true
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: mykey
      ImageTagMutability: IMMUTABLE
      RepositoryPolicyText: 
        Version: "2012-10-17"
        Statement: 
          - 
            Sid: AllowPushPull
            Effect: Allow
            Principal: 
              AWS: 
                - "arn:aws:iam::123456789012:user/Alice"
            Action: 
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
  `,
			expected: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						ImageTagsImmutable: types.BoolTest(true),
						ImageScanning: ecr.ImageScanning{
							ScanOnPush: types.BoolTest(true),
						},
						Encryption: ecr.Encryption{
							Type:     types.StringTest("KMS"),
							KMSKeyID: types.StringTest("mykey"),
						},
						Policies: []iam.Policy{
							{
								Document: func() iam.Document {
									return iam.Document{
										Parsed: iamgo.NewPolicyBuilder().
											WithVersion("2012-10-17").
											WithStatement(
												iamgo.NewStatementBuilder().
													WithSid("AllowPushPull").
													WithEffect("Allow").
													WithAWSPrincipals(
														[]string{"arn:aws:iam::123456789012:user/Alice"},
													).
													WithActions(
														[]string{
															"ecr:GetDownloadUrlForLayer",
															"ecr:BatchGetImage",
														},
													).
													Build(),
											).
											Build(),
									}
								}(),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
