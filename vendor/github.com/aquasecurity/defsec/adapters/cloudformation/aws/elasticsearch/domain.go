package elasticsearch

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/elasticsearch"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourceByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {

		domain := elasticsearch.Domain{
			Metadata:   r.Metadata(),
			DomainName: r.GetStringProperty("DomainName"),
			LogPublishing: elasticsearch.LogPublishing{
				AuditEnabled: r.GetBoolProperty("LogPublishingOptions.Enabled"),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Enabled: r.GetBoolProperty("NodeToNodeEncryptionOptions.Enabled"),
			},
			AtRestEncryption: elasticsearch.AtRestEncryption{
				Enabled: r.GetBoolProperty("EncryptionAtRestOptions.Enabled"),
			},
			Endpoint: elasticsearch.Endpoint{
				EnforceHTTPS: r.GetBoolProperty("DomainEndpointOptions.EnforceHTTPS"),
				TLSPolicy:    r.GetStringProperty("DomainEndpointOptions.TLSSecurityPolicy"),
			},
		}

		domains = append(domains, domain)
	}

	return domains
}
