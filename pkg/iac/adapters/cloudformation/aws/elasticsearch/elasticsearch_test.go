package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected elasticsearch.Elasticsearch
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  OpenSearchServiceDomain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: 'test'
      ClusterConfig:
        DedicatedMasterEnabled: true
      NodeToNodeEncryptionOptions:
        Enabled: true
      EncryptionAtRestOptions:
        Enabled: true
        KmsKeyId: mykey
      DomainEndpointOptions:
        EnforceHTTPS: true
        TLSSecurityPolicy: Policy-Min-TLS-1-0-2019-07
      AccessPolicies:
        Version: '2012-10-17'
        Statement:
          -
            Effect: 'Allow'
            Principal:
              AWS: 'arn:aws:iam::123456789012:user/opensearch-user'
            Action: 'es:*'
            Resource: 'arn:aws:es:us-east-1:846973539254:domain/test/*'
      LogPublishingOptions:
        AUDIT_LOGS:
            CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/opensearch/domains/opensearch-application-logs'
            Enabled: true
`,
			expected: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						DomainName:             types.StringTest("test"),
						DedicatedMasterEnabled: types.BoolTest(true),
						LogPublishing: elasticsearch.LogPublishing{
							AuditEnabled:          types.BoolTest(true),
							CloudWatchLogGroupArn: types.StringTest("arn:aws:logs:us-east-1:123456789012:log-group:/aws/opensearch/domains/opensearch-application-logs"),
						},
						TransitEncryption: elasticsearch.TransitEncryption{
							Enabled: types.BoolTest(true),
						},
						AtRestEncryption: elasticsearch.AtRestEncryption{
							Enabled:  types.BoolTest(true),
							KmsKeyId: types.StringTest("mykey"),
						},
						Endpoint: elasticsearch.Endpoint{
							EnforceHTTPS: types.BoolTest(true),
							TLSPolicy:    types.StringTest("Policy-Min-TLS-1-0-2019-07"),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  OpenSearchServiceDomain:
    Type: AWS::OpenSearchService::Domain
  `,
			expected: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{{}},
			},
		},
		{
			name: "Elasticsearch",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
  `,
			expected: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						DedicatedMasterEnabled: types.BoolTest(true),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
