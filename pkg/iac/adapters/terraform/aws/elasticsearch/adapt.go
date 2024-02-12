package elasticsearch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
		Metadata:               resource.GetMetadata(),
		DomainName:             defsecTypes.StringDefault("", resource.GetMetadata()),
		AccessPolicies:         resource.GetAttribute("access_policies").AsStringValueOrDefault("", resource),
		VpcId:                  resource.GetAttribute("vpc_options.0.vpc_id").AsStringValueOrDefault("", resource),
		DedicatedMasterEnabled: defsecTypes.Bool(false, resource.GetMetadata()),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:              resource.GetMetadata(),
			AuditEnabled:          defsecTypes.BoolDefault(false, resource.GetMetadata()),
			CloudWatchLogGroupArn: defsecTypes.String("", resource.GetMetadata()),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  defsecTypes.BoolDefault(false, resource.GetMetadata()),
			KmsKeyId: defsecTypes.String("", resource.GetMetadata()),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     resource.GetMetadata(),
			EnforceHTTPS: defsecTypes.BoolDefault(false, resource.GetMetadata()),
			TLSPolicy:    defsecTypes.StringDefault("", resource.GetMetadata()),
		},
		ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
			Metadata:        resource.GetMetadata(),
			CurrentVersion:  defsecTypes.String("", resource.GetMetadata()),
			NewVersion:      defsecTypes.String("", resource.GetMetadata()),
			UpdateAvailable: defsecTypes.Bool(false, resource.GetMetadata()),
			UpdateStatus:    defsecTypes.String("", resource.GetMetadata()),
		},
	}

	nameAttr := resource.GetAttribute("domain_name")
	domain.DomainName = nameAttr.AsStringValueOrDefault("", resource)

	for _, logOptionsBlock := range resource.GetBlocks("log_publishing_options") {
		domain.LogPublishing.Metadata = logOptionsBlock.GetMetadata()
		domain.LogPublishing.CloudWatchLogGroupArn = logOptionsBlock.GetAttribute("cloudwatch_log_group_arn").AsStringValueOrDefault("", resource)
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

	if clusterconfigBlock := resource.GetBlock("cluster_config"); clusterconfigBlock.IsNotNil() {
		domain.DedicatedMasterEnabled = clusterconfigBlock.GetAttribute("dedicated_master_enabled").AsBoolValueOrDefault(false, clusterconfigBlock)
	}

	if atRestEncryptBlock := resource.GetBlock("encrypt_at_rest"); atRestEncryptBlock.IsNotNil() {
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		domain.AtRestEncryption.Metadata = atRestEncryptBlock.GetMetadata()
		domain.AtRestEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, atRestEncryptBlock)
		domain.AtRestEncryption.KmsKeyId = atRestEncryptBlock.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource)
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
