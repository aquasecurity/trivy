package elasticsearch

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts an ElasticSearch instance
func Adapt(cfFile parser.FileContext) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{
		Domains: getDomains(cfFile),
	}
}
