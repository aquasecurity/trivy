package dynamodb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourcesByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Metadata: r.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
				KMSKeyID: defsecTypes.StringDefault("", r.Metadata()),
			},
			PointInTimeRecovery: defsecTypes.BoolUnresolvable(r.Metadata()),
		}

		if sseProp := r.GetProperty("SSESpecification"); sseProp.IsNotNil() {
			cluster.ServerSideEncryption = dynamodb.ServerSideEncryption{
				Metadata: sseProp.Metadata(),
				Enabled:  r.GetBoolProperty("SSESpecification.SSEEnabled"),
				KMSKeyID: defsecTypes.StringUnresolvable(sseProp.Metadata()),
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
