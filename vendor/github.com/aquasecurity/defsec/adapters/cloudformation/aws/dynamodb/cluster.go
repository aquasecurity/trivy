package dynamodb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourceByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Enabled: r.GetBoolProperty("SSESpecification.SSEEnabled"),
			},
			PointInTimeRecovery: nil,
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
