package elasticsearch

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourcesByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {

		domain := elasticsearch.Domain{
			Metadata:       r.Metadata(),
			DomainName:     r.GetStringProperty("DomainName"),
			AccessPolicies: r.GetStringProperty("AccessPolicies"),
			VpcId:          iacTypes.String("", r.Metadata()),
			LogPublishing: elasticsearch.LogPublishing{
				Metadata:              r.Metadata(),
				AuditEnabled:          iacTypes.BoolDefault(false, r.Metadata()),
				CloudWatchLogGroupArn: iacTypes.String("", r.Metadata()),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Metadata: r.Metadata(),
				Enabled:  iacTypes.BoolDefault(false, r.Metadata()),
			},
			AtRestEncryption: elasticsearch.AtRestEncryption{
				Metadata: r.Metadata(),
				Enabled:  iacTypes.BoolDefault(false, r.Metadata()),
				KmsKeyId: iacTypes.String("", r.Metadata()),
			},
			Endpoint: elasticsearch.Endpoint{
				Metadata:     r.Metadata(),
				EnforceHTTPS: iacTypes.BoolDefault(false, r.Metadata()),
			},
			ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
				Metadata:        r.Metadata(),
				CurrentVersion:  iacTypes.String("", r.Metadata()),
				NewVersion:      iacTypes.String("", r.Metadata()),
				UpdateStatus:    iacTypes.String("", r.Metadata()),
				UpdateAvailable: iacTypes.Bool(false, r.Metadata()),
			},
		}

		if r.Type() == "AWS::OpenSearchService::Domain" {
			domain.DedicatedMasterEnabled = r.GetBoolProperty("ClusterConfig.DedicatedMasterEnabled")
		} else {
			domain.DedicatedMasterEnabled = r.GetBoolProperty("ElasticsearchClusterConfig.DedicatedMasterEnabled")
		}

		if prop := r.GetProperty("LogPublishingOptions"); prop.IsNotNil() {
			domain.LogPublishing = elasticsearch.LogPublishing{
				Metadata:              prop.Metadata(),
				AuditEnabled:          prop.GetBoolProperty("AUDIT_LOGS.Enabled"),
				CloudWatchLogGroupArn: prop.GetStringProperty("AUDIT_LOGS.CloudWatchLogsLogGroupArn"),
			}
		}

		if prop := r.GetProperty("NodeToNodeEncryptionOptions"); prop.IsNotNil() {
			domain.TransitEncryption = elasticsearch.TransitEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled"),
			}
		}

		if prop := r.GetProperty("EncryptionAtRestOptions"); prop.IsNotNil() {
			domain.AtRestEncryption = elasticsearch.AtRestEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled"),
				KmsKeyId: prop.GetStringProperty("KmsKeyId"),
			}
		}

		if prop := r.GetProperty("DomainEndpointOptions"); prop.IsNotNil() {
			domain.Endpoint = elasticsearch.Endpoint{
				Metadata:     prop.Metadata(),
				EnforceHTTPS: prop.GetBoolProperty("EnforceHTTPS"),
				TLSPolicy:    prop.GetStringProperty("TLSSecurityPolicy"),
			}
		}

		domains = append(domains, domain)
	}

	return domains
}
