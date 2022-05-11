package elasticsearch

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{
		Domains: adaptDomains(modules),
	}
}

func adaptDomains(modules terraform.Modules) []elasticsearch.Domain {
	var domains []elasticsearch.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticsearch_domain") {
			domains = append(domains, adaptDomain(resource))
		}
	}
	return domains
}

func adaptDomain(resource *terraform.Block) elasticsearch.Domain {
	domain := elasticsearch.Domain{
		Metadata:   resource.GetMetadata(),
		DomainName: types.StringDefault("", resource.GetMetadata()),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:     resource.GetMetadata(),
			AuditEnabled: types.BoolDefault(false, resource.GetMetadata()),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types.BoolDefault(false, resource.GetMetadata()),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     resource.GetMetadata(),
			EnforceHTTPS: types.BoolDefault(false, resource.GetMetadata()),
			TLSPolicy:    types.StringDefault("", resource.GetMetadata()),
		},
	}

	nameAttr := resource.GetAttribute("domain_name")
	domain.DomainName = nameAttr.AsStringValueOrDefault("", resource)

	for _, logOptionsBlock := range resource.GetBlocks("log_publishing_options") {
		domain.LogPublishing.Metadata = logOptionsBlock.GetMetadata()
		enabledAttr := logOptionsBlock.GetAttribute("enabled")
		enabledVal := enabledAttr.AsBoolValueOrDefault(true, logOptionsBlock)
		logTypeAttr := logOptionsBlock.GetAttribute("log_type")
		if logTypeAttr.Equals("AUDIT_LOGS") {
			domain.LogPublishing.AuditEnabled = enabledVal
		}
	}

	if transitEncryptBlock := resource.GetBlock("node_to_node_encryption"); transitEncryptBlock.IsNotNil() {
		enabledAttr := transitEncryptBlock.GetAttribute("enabled")
		domain.TransitEncryption.Metadata = transitEncryptBlock.GetMetadata()
		domain.TransitEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, transitEncryptBlock)
	}

	if atRestEncryptBlock := resource.GetBlock("encrypt_at_rest"); atRestEncryptBlock.IsNotNil() {
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		domain.AtRestEncryption.Metadata = atRestEncryptBlock.GetMetadata()
		domain.AtRestEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, atRestEncryptBlock)
	}

	if endpointBlock := resource.GetBlock("domain_endpoint_options"); endpointBlock.IsNotNil() {
		domain.Endpoint.Metadata = endpointBlock.GetMetadata()
		enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
		domain.Endpoint.EnforceHTTPS = enforceHTTPSAttr.AsBoolValueOrDefault(true, endpointBlock)
		TLSPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
		domain.Endpoint.TLSPolicy = TLSPolicyAttr.AsStringValueOrDefault("", endpointBlock)
	}

	return domain
}
