package cloudfront

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata: defsecTypes.NewTestMetadata(),
				WAFID:    defsecTypes.String("waf_id", defsecTypes.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Bucket:   defsecTypes.String("mylogs.s3.amazonaws.com", defsecTypes.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             defsecTypes.NewTestMetadata(),
					ViewerProtocolPolicy: defsecTypes.String("redirect-to-https", defsecTypes.NewTestMetadata()),
				},
				OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						ViewerProtocolPolicy: defsecTypes.String("redirect-to-https", defsecTypes.NewTestMetadata()),
					},
				},
				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:                     defsecTypes.NewTestMetadata(),
					MinimumProtocolVersion:       defsecTypes.String("TLSv1.2_2021", defsecTypes.NewTestMetadata()),
					CloudfrontDefaultCertificate: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					SSLSupportMethod:             defsecTypes.String("sni-only", defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				WAFID:    defsecTypes.String("", defsecTypes.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: defsecTypes.NewTestMetadata(),
					Bucket:   defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             defsecTypes.NewTestMetadata(),
					ViewerProtocolPolicy: defsecTypes.String("allow-all", defsecTypes.NewTestMetadata()),
				},

				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:               defsecTypes.NewTestMetadata(),
					MinimumProtocolVersion: defsecTypes.String("TLSv1", defsecTypes.NewTestMetadata()),
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
