package cloudfront

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptDistribution(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudfront.Distribution
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {
				logging_config {
					bucket          = "mylogs.s3.amazonaws.com"
				}
				
				web_acl_id = "waf_id"

				default_cache_behavior {
					viewer_protocol_policy = "redirect-to-https"
				}

				ordered_cache_behavior {
					viewer_protocol_policy = "redirect-to-https"
				  }

				viewer_certificate {
					cloudfront_default_certificate = true
					minimum_protocol_version = "TLSv1.2_2021"
					ssl_support_method = "sni-only"
				}
			}
`,
			expected: cloudfront.Distribution{
				WAFID: iacTypes.StringTest("waf_id"),
				Logging: cloudfront.Logging{
					Bucket: iacTypes.StringTest("mylogs.s3.amazonaws.com"),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					ViewerProtocolPolicy: iacTypes.StringTest("redirect-to-https"),
				},
				OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
					{
						ViewerProtocolPolicy: iacTypes.StringTest("redirect-to-https"),
					},
				},
				ViewerCertificate: cloudfront.ViewerCertificate{
					MinimumProtocolVersion:       iacTypes.StringTest("TLSv1.2_2021"),
					CloudfrontDefaultCertificate: iacTypes.BoolTest(true),
					SSLSupportMethod:             iacTypes.StringTest("sni-only"),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {
			}
`,
			expected: cloudfront.Distribution{
				Logging:               cloudfront.Logging{},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{},

				ViewerCertificate: cloudfront.ViewerCertificate{
					MinimumProtocolVersion: iacTypes.StringTest("TLSv1"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDistribution(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptDistributionV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudfront.Distribution
	}{
		{
			name: "v2 logging configured",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {}

			resource "aws_cloudwatch_log_delivery_source" "example" {
				log_type     = "ACCESS_LOGS"
				resource_arn = aws_cloudfront_distribution.example.arn
			}

			resource "aws_cloudwatch_log_delivery" "example" {
				delivery_source_name = aws_cloudwatch_log_delivery_source.example.name
			}
`,
			expected: cloudfront.Distribution{
				Logging: cloudfront.Logging{
					V2: cloudfront.LoggingV2{
						Enabled: iacTypes.BoolTest(true),
					},
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{},
				ViewerCertificate: cloudfront.ViewerCertificate{
					MinimumProtocolVersion: iacTypes.StringTest("TLSv1"),
				},
			},
		},
		{
			name: "v2 logging source exists but no delivery",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {}

			resource "aws_cloudwatch_log_delivery_source" "example" {
				log_type     = "ACCESS_LOGS"
				resource_arn = aws_cloudfront_distribution.example.arn
			}
`,
			expected: cloudfront.Distribution{
				Logging: cloudfront.Logging{
					V2: cloudfront.LoggingV2{
						Enabled: iacTypes.BoolTest(false),
					},
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{},
				ViewerCertificate: cloudfront.ViewerCertificate{
					MinimumProtocolVersion: iacTypes.StringTest("TLSv1"),
				},
			},
		},

		{
			name: "v2 logging with non-access log_type",
			terraform: `
            resource "aws_cloudfront_distribution" "example" {}

            resource "aws_cloudwatch_log_delivery_source" "example" {
                log_type     = "ERROR_LOGS"
                resource_arn = aws_cloudfront_distribution.example.arn
            }

            resource "aws_cloudwatch_log_delivery" "example" {
                delivery_source_name = aws_cloudwatch_log_delivery_source.example.name
            }
`,
			expected: cloudfront.Distribution{
				Logging: cloudfront.Logging{
					V2: cloudfront.LoggingV2{
						Enabled: iacTypes.BoolTest(false),
					},
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{},
				ViewerCertificate: cloudfront.ViewerCertificate{
					MinimumProtocolVersion: iacTypes.StringTest("TLSv1"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			require.Len(t, adapted.Distributions, 1)
			testutil.AssertDefsecEqual(t, test.expected, adapted.Distributions[0])
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudfront_distribution" "example" {
		logging_config {
			bucket          = "mylogs.s3.amazonaws.com"
		}
		
		web_acl_id = "waf_id"

		default_cache_behavior {
			viewer_protocol_policy = "redirect-to-https"
		}

		ordered_cache_behavior {
			viewer_protocol_policy = "redirect-to-https"
		}

		viewer_certificate {
			cloudfront_default_certificate = true
			minimum_protocol_version = "TLSv1.2_2021"
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Distributions, 1)
	distribution := adapted.Distributions[0]

	assert.Equal(t, 2, distribution.Metadata.Range().GetStartLine())
	assert.Equal(t, 21, distribution.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, distribution.Logging.Metadata.Range().GetStartLine())
	assert.Equal(t, 5, distribution.Logging.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, distribution.WAFID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, distribution.WAFID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, distribution.DefaultCacheBehaviour.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, distribution.DefaultCacheBehaviour.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, distribution.DefaultCacheBehaviour.ViewerProtocolPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, distribution.DefaultCacheBehaviour.ViewerProtocolPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, distribution.OrdererCacheBehaviours[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 15, distribution.OrdererCacheBehaviours[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, distribution.OrdererCacheBehaviours[0].ViewerProtocolPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, distribution.OrdererCacheBehaviours[0].ViewerProtocolPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, distribution.ViewerCertificate.Metadata.Range().GetStartLine())
	assert.Equal(t, 20, distribution.ViewerCertificate.Metadata.Range().GetEndLine())

	assert.Equal(t, 19, distribution.ViewerCertificate.MinimumProtocolVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, distribution.ViewerCertificate.MinimumProtocolVersion.GetMetadata().Range().GetEndLine())
}
