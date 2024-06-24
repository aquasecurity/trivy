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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
