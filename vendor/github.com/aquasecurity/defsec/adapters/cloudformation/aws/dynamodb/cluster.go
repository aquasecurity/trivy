package dynamodb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourcesByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Metadata: r.Metadata(),
				Enabled:  types.BoolDefault(false, r.Metadata()),
				KMSKeyID: types.StringDefault("", r.Metadata()),
			},
			PointInTimeRecovery: types.BoolUnresolvable(r.Metadata()),
		}

		if sseProp := r.GetProperty("SSESpecification"); sseProp.IsNotNil() {
			cluster.ServerSideEncryption = dynamodb.ServerSideEncryption{
				Metadata: sseProp.Metadata(),
				Enabled:  r.GetBoolProperty("SSESpecification.SSEEnabled"),
				KMSKeyID: types.StringUnresolvable(sseProp.Metadata()),
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
