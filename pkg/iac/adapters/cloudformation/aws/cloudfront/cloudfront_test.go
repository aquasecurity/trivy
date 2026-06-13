package cloudfront

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected cloudfront.Cloudfront
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  cloudfrontdistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        WebACLId: "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
        Logging:
          Bucket: "myawslogbucket.s3.amazonaws.com"
        ViewerCertificate:
          MinimumProtocolVersion: SSLv3
        DefaultCacheBehavior:
          ViewerProtocolPolicy: "redirect-to-https"
`,
			expected: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						WAFID: types.StringTest("a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"),
						Logging: cloudfront.Logging{
							Bucket: types.StringTest("myawslogbucket.s3.amazonaws.com"),
						},
						ViewerCertificate: cloudfront.ViewerCertificate{
							MinimumProtocolVersion: types.StringTest("SSLv3"),
						},
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							ViewerProtocolPolicy: types.StringTest("redirect-to-https"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  cloudfrontdistribution:
    Type: AWS::CloudFront::Distribution
`,
			expected: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{{}},
			},
		},

		{
			name: "v2 logging configured",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  CloudFrontDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          ViewerProtocolPolicy: "redirect-to-https"

  CloudFrontAccessLogsDeliverySource:
    Type: AWS::Logs::DeliverySource
    Properties:
      LogType: ACCESS_LOGS
      Name: cloudfront-log-delivery-source
      ResourceArn: !Sub
        - arn:aws:cloudfront::${AWS::AccountId}:distribution/${D}
        - D: !GetAtt CloudFrontDistribution.Id

  CloudFrontAccessLogsDelivery:
    Type: AWS::Logs::Delivery
    Properties:
      DeliverySourceName: cloudfront-log-delivery-source
`,
			expected: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Logging: cloudfront.Logging{
							V2: cloudfront.LoggingV2{
								Enabled: types.BoolTest(true),
							},
						},
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							ViewerProtocolPolicy: types.StringTest("redirect-to-https"),
						},
					},
				},
			},
		},
		{
			name: "v2 logging source exists but no delivery",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  CloudFrontDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          ViewerProtocolPolicy: "redirect-to-https"

  CloudFrontAccessLogsDeliverySource:
    Type: AWS::Logs::DeliverySource
    Properties:
      LogType: ACCESS_LOGS
      Name: cloudfront-log-delivery-source
      ResourceArn: !Sub
        - arn:aws:cloudfront::${AWS::AccountId}:distribution/${D}
        - D: !GetAtt CloudFrontDistribution.Id
`,
			expected: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Logging: cloudfront.Logging{
							V2: cloudfront.LoggingV2{
								Enabled: types.BoolTest(false),
							},
						},
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							ViewerProtocolPolicy: types.StringTest("redirect-to-https"),
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
