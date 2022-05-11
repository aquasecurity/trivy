package documentdb

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters []documentdb.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::DocDB::DBCluster")

	for _, r := range clusterResources {
		cluster := documentdb.Cluster{
			Metadata:          r.Metadata(),
			Identifier:        r.GetStringProperty("DBClusterIdentifier"),
			EnabledLogExports: getLogExports(r),
			Instances:         nil,
			StorageEncrypted:  r.GetBoolProperty("StorageEncrypted"),
			KMSKeyID:          r.GetStringProperty("KmsKeyId"),
		}

		updateInstancesOnCluster(&cluster, ctx)

		clusters = append(clusters, cluster)
	}
	return clusters
}

func updateInstancesOnCluster(cluster *documentdb.Cluster, ctx parser.FileContext) {

	instanceResources := ctx.GetResourcesByType("AWS::DocDB::DBInstance")

	for _, r := range instanceResources {
		clusterIdentifier := r.GetStringProperty("DBClusterIdentifier")
		if clusterIdentifier == cluster.Identifier {
			cluster.Instances = append(cluster.Instances, documentdb.Instance{
				Metadata: r.Metadata(),
				KMSKeyID: cluster.KMSKeyID,
			})
		}
	}
}

func getLogExports(r *parser.Resource) (logExports []types.StringValue) {

	exportsList := r.GetProperty("EnableCloudwatchLogsExports")

	if exportsList.IsNil() || exportsList.IsNotList() {
		return logExports
	}

	for _, export := range exportsList.AsList() {
		logExports = append(logExports, export.AsStringValue())
	}
	return logExports
}
