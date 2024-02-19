package neptune

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/neptune"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClusters(ctx parser2.FileContext) (clusters []neptune.Cluster) {
	for _, r := range ctx.GetResourcesByType("AWS::Neptune::DBCluster") {

		cluster := neptune.Cluster{
			Metadata: r.Metadata(),
			Logging: neptune.Logging{
				Metadata: r.Metadata(),
				Audit:    getAuditLog(r),
			},
			StorageEncrypted: r.GetBoolProperty("StorageEncrypted"),
			KMSKeyID:         r.GetStringProperty("KmsKeyId"),
		}
		clusters = append(clusters, cluster)
	}
	return clusters
}

func getAuditLog(r *parser2.Resource) types.BoolValue {
	if logsProp := r.GetProperty("EnableCloudwatchLogsExports"); logsProp.IsList() {
		if logsProp.Contains("audit") {
			return types.Bool(true, logsProp.Metadata())
		}
	}

	return types.BoolDefault(false, r.Metadata())
}
