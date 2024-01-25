package elasticsearch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourcesByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {

		domain := elasticsearch.Domain{
			Metadata:               r.Metadata(),
			DomainName:             r.GetStringProperty("DomainName"),
			AccessPolicies:         r.GetStringProperty("AccessPolicies"),
			DedicatedMasterEnabled: r.GetBoolProperty("ElasticsearchClusterConfig.DedicatedMasterEnabled"),
			VpcId:                  defsecTypes.String("", r.Metadata()),
			LogPublishing: elasticsearch.LogPublishing{
				Metadata:              r.Metadata(),
				AuditEnabled:          defsecTypes.BoolDefault(false, r.Metadata()),
				CloudWatchLogGroupArn: defsecTypes.String("", r.Metadata()),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Metadata: r.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
			},
			AtRestEncryption: elasticsearch.AtRestEncryption{
				Metadata: r.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
				KmsKeyId: defsecTypes.String("", r.Metadata()),
			},
			Endpoint: elasticsearch.Endpoint{
				Metadata:     r.Metadata(),
				EnforceHTTPS: defsecTypes.BoolDefault(false, r.Metadata()),
				TLSPolicy:    defsecTypes.StringDefault("Policy-Min-TLS-1-0-2019-07", r.Metadata()),
			},
			ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
				Metadata:        r.Metadata(),
				CurrentVersion:  defsecTypes.String("", r.Metadata()),
				NewVersion:      defsecTypes.String("", r.Metadata()),
				UpdateStatus:    defsecTypes.String("", r.Metadata()),
				UpdateAvailable: defsecTypes.Bool(false, r.Metadata()),
			},
		}

		if prop := r.GetProperty("LogPublishingOptions"); prop.IsNotNil() {
			domain.LogPublishing = elasticsearch.LogPublishing{
				Metadata:              prop.Metadata(),
				AuditEnabled:          prop.GetBoolProperty("AUDIT_LOGS.Enabled", false),
				CloudWatchLogGroupArn: prop.GetStringProperty("CloudWatchLogsLogGroupArn"),
			}
		}

		if prop := r.GetProperty("NodeToNodeEncryptionOptions"); prop.IsNotNil() {
			domain.TransitEncryption = elasticsearch.TransitEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled", false),
			}
		}

		if prop := r.GetProperty("EncryptionAtRestOptions"); prop.IsNotNil() {
			domain.AtRestEncryption = elasticsearch.AtRestEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled", false),
				KmsKeyId: prop.GetStringProperty("KmsKeyId"),
			}
		}

		if prop := r.GetProperty("DomainEndpointOptions"); prop.IsNotNil() {
			domain.Endpoint = elasticsearch.Endpoint{
				Metadata:     prop.Metadata(),
				EnforceHTTPS: prop.GetBoolProperty("EnforceHTTPS", false),
				TLSPolicy:    prop.GetStringProperty("TLSSecurityPolicy", "Policy-Min-TLS-1-0-2019-07"),
			}
		}

		domains = append(domains, domain)
	}

	return domains
}
