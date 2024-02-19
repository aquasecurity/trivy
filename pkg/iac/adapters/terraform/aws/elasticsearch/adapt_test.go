package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptDomain(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elasticsearch.Domain
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_elasticsearch_domain" "example" {
				domain_name = "domain-foo"
			  
				node_to_node_encryption {
					enabled = true
				}
	 
				encrypt_at_rest {
					enabled = true
				}

				domain_endpoint_options {
				  enforce_https = true
				  tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
				}

				log_publishing_options {
					cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
					log_type                 = "AUDIT_LOGS"
					enabled                  = true  
				}
			  }
`,
			expected: elasticsearch.Domain{
				Metadata:   iacTypes.NewTestMetadata(),
				DomainName: iacTypes.String("domain-foo", iacTypes.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     iacTypes.NewTestMetadata(),
					AuditEnabled: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     iacTypes.NewTestMetadata(),
					EnforceHTTPS: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					TLSPolicy:    iacTypes.String("Policy-Min-TLS-1-2-2019-07", iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_elasticsearch_domain" "example" {
			  }
`,
			expected: elasticsearch.Domain{
				Metadata:   iacTypes.NewTestMetadata(),
				DomainName: iacTypes.String("", iacTypes.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     iacTypes.NewTestMetadata(),
					AuditEnabled: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     iacTypes.NewTestMetadata(),
					EnforceHTTPS: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					TLSPolicy:    iacTypes.String("", iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDomain(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_elasticsearch_domain" "example" {
		domain_name = "domain-foo"
	  
		node_to_node_encryption {
			enabled = true
		}

		encrypt_at_rest {
			enabled = true
		}

		domain_endpoint_options {
		  enforce_https = true
		  tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
		}

		log_publishing_options {
			cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
			log_type                 = "AUDIT_LOGS"
			enabled                  = true  
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Domains, 1)
	domain := adapted.Domains[0]

	assert.Equal(t, 2, domain.Metadata.Range().GetStartLine())
	assert.Equal(t, 23, domain.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, domain.DomainName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, domain.DomainName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, domain.TransitEncryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, domain.TransitEncryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, domain.TransitEncryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, domain.TransitEncryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, domain.AtRestEncryption.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, domain.AtRestEncryption.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, domain.AtRestEncryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, domain.AtRestEncryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, domain.Endpoint.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, domain.Endpoint.Metadata.Range().GetEndLine())

	assert.Equal(t, 14, domain.Endpoint.EnforceHTTPS.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, domain.Endpoint.EnforceHTTPS.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, domain.Endpoint.TLSPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, domain.Endpoint.TLSPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, domain.LogPublishing.Metadata.Range().GetStartLine())
	assert.Equal(t, 22, domain.LogPublishing.Metadata.Range().GetEndLine())

	assert.Equal(t, 21, domain.LogPublishing.AuditEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, domain.LogPublishing.AuditEnabled.GetMetadata().Range().GetEndLine())
}
