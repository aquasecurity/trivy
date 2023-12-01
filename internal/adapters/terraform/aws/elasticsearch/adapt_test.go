package elasticsearch

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
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
				Metadata:   defsecTypes.NewTestMetadata(),
				DomainName: defsecTypes.String("domain-foo", defsecTypes.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     defsecTypes.NewTestMetadata(),
					AuditEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     defsecTypes.NewTestMetadata(),
					EnforceHTTPS: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					TLSPolicy:    defsecTypes.String("Policy-Min-TLS-1-2-2019-07", defsecTypes.NewTestMetadata()),
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
				Metadata:   defsecTypes.NewTestMetadata(),
				DomainName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     defsecTypes.NewTestMetadata(),
					AuditEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     defsecTypes.NewTestMetadata(),
					EnforceHTTPS: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					TLSPolicy:    defsecTypes.String("", defsecTypes.NewTestMetadata()),
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
