package dynamodb

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourcesByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Metadata: r.Metadata(),
				Enabled:  iacTypes.BoolDefault(false, r.Metadata()),
				KMSKeyID: iacTypes.StringDefault("", r.Metadata()),
			},
			PointInTimeRecovery: iacTypes.BoolUnresolvable(r.Metadata()),
		}

		if sseProp := r.GetProperty("SSESpecification"); sseProp.IsNotNil() {
			cluster.ServerSideEncryption = dynamodb.ServerSideEncryption{
				Metadata: sseProp.Metadata(),
				Enabled:  r.GetBoolProperty("SSESpecification.SSEEnabled"),
				KMSKeyID: iacTypes.StringUnresolvable(sseProp.Metadata()),
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
