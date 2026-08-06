package elasticsearch

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{
		Domains: adaptDomains(modules),
	}
}

func adaptDomains(modules terraform.Modules) []elasticsearch.Domain {
	var domains []elasticsearch.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticsearch_domain", "aws_opensearch_domain") {
			domains = append(domains, adaptDomain(resource))
		}
	}
	return domains
}

func adaptDomain(resource *terraform.Block) elasticsearch.Domain {
	domain := elasticsearch.Domain{
		Metadata:               resource.GetMetadata(),
		DomainName:             iacTypes.StringDefault("", resource.GetMetadata()),
		AccessPolicies:         resource.GetAttribute("access_policies").AsStringValue(),
		VpcId:                  resource.GetAttribute("vpc_options.0.vpc_id").AsStringValue(),
		DedicatedMasterEnabled: iacTypes.Bool(false, resource.GetMetadata()),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:              resource.GetMetadata(),
			AuditEnabled:          iacTypes.BoolDefault(false, resource.GetMetadata()),
			CloudWatchLogGroupArn: iacTypes.String("", resource.GetMetadata()),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			KmsKeyId: iacTypes.String("", resource.GetMetadata()),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     resource.GetMetadata(),
			EnforceHTTPS: iacTypes.BoolDefault(false, resource.GetMetadata()),
			TLSPolicy:    iacTypes.StringDefault("", resource.GetMetadata()),
		},
		ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
			Metadata:        resource.GetMetadata(),
			CurrentVersion:  iacTypes.String("", resource.GetMetadata()),
			NewVersion:      iacTypes.String("", resource.GetMetadata()),
			UpdateAvailable: iacTypes.Bool(false, resource.GetMetadata()),
			UpdateStatus:    iacTypes.String("", resource.GetMetadata()),
		},
	}

	nameAttr := resource.GetAttribute("domain_name")
	domain.DomainName = nameAttr.AsStringValue()

	for _, logOptionsBlock := range resource.GetBlocks("log_publishing_options") {
		domain.LogPublishing.Metadata = logOptionsBlock.GetMetadata()
		domain.LogPublishing.CloudWatchLogGroupArn = logOptionsBlock.GetAttribute("cloudwatch_log_group_arn").AsStringValue()
		enabledAttr := logOptionsBlock.GetAttribute("enabled")
		enabledVal := enabledAttr.AsBoolValue(true)
		logTypeAttr := logOptionsBlock.GetAttribute("log_type")
		if logTypeAttr.Equals("AUDIT_LOGS") {
			domain.LogPublishing.AuditEnabled = enabledVal
		}
	}

	if transitEncryptBlock := resource.GetBlock("node_to_node_encryption"); transitEncryptBlock.IsNotNil() {
		enabledAttr := transitEncryptBlock.GetAttribute("enabled")
		domain.TransitEncryption.Metadata = transitEncryptBlock.GetMetadata()
		domain.TransitEncryption.Enabled = enabledAttr.AsBoolValue()
	}

	if clusterconfigBlock := resource.GetBlock("cluster_config"); clusterconfigBlock.IsNotNil() {
		domain.DedicatedMasterEnabled = clusterconfigBlock.GetAttribute("dedicated_master_enabled").AsBoolValue()
	}

	if atRestEncryptBlock := resource.GetBlock("encrypt_at_rest"); atRestEncryptBlock.IsNotNil() {
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		domain.AtRestEncryption.Metadata = atRestEncryptBlock.GetMetadata()
		domain.AtRestEncryption.Enabled = enabledAttr.AsBoolValue()
		domain.AtRestEncryption.KmsKeyId = atRestEncryptBlock.GetAttribute("kms_key_id").AsStringValue()
	}

	if endpointBlock := resource.GetBlock("domain_endpoint_options"); endpointBlock.IsNotNil() {
		domain.Endpoint.Metadata = endpointBlock.GetMetadata()
		enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
		domain.Endpoint.EnforceHTTPS = enforceHTTPSAttr.AsBoolValue(true)
		TLSPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
		domain.Endpoint.TLSPolicy = TLSPolicyAttr.AsStringValue()
	}

	return domain
}
