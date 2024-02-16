package cloudfront

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata: iacTypes.NewTestMetadata(),
				WAFID:    iacTypes.String("waf_id", iacTypes.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: iacTypes.NewTestMetadata(),
					Bucket:   iacTypes.String("mylogs.s3.amazonaws.com", iacTypes.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             iacTypes.NewTestMetadata(),
					ViewerProtocolPolicy: iacTypes.String("redirect-to-https", iacTypes.NewTestMetadata()),
				},
				OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
					{
						Metadata:             iacTypes.NewTestMetadata(),
						ViewerProtocolPolicy: iacTypes.String("redirect-to-https", iacTypes.NewTestMetadata()),
					},
				},
				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:                     iacTypes.NewTestMetadata(),
					MinimumProtocolVersion:       iacTypes.String("TLSv1.2_2021", iacTypes.NewTestMetadata()),
					CloudfrontDefaultCertificate: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					SSLSupportMethod:             iacTypes.String("sni-only", iacTypes.NewTestMetadata()),
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
				Metadata: iacTypes.NewTestMetadata(),
				WAFID:    iacTypes.String("", iacTypes.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: iacTypes.NewTestMetadata(),
					Bucket:   iacTypes.String("", iacTypes.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             iacTypes.NewTestMetadata(),
					ViewerProtocolPolicy: iacTypes.String("allow-all", iacTypes.NewTestMetadata()),
				},

				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:               iacTypes.NewTestMetadata(),
					MinimumProtocolVersion: iacTypes.String("TLSv1", iacTypes.NewTestMetadata()),
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
