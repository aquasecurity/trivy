package redshift

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters []redshift.Cluster) {
	for _, r := range ctx.GetResourcesByType("AWS::Redshift::Cluster") {

		cluster := redshift.Cluster{
			Metadata:                         r.Metadata(),
			ClusterIdentifier:                r.GetStringProperty("ClusterIdentifier"),
			AllowVersionUpgrade:              r.GetBoolProperty("AllowVersionUpgrade", true),
			NodeType:                         r.GetStringProperty("NodeType"),
			NumberOfNodes:                    r.GetIntProperty("NumberOfNodes", 1),
			PubliclyAccessible:               r.GetBoolProperty("PubliclyAccessible"),
			MasterUsername:                   r.GetStringProperty("MasterUsername"),
			AutomatedSnapshotRetentionPeriod: r.GetIntProperty("AutomatedSnapshotRetentionPeriod", 1),
			Encryption: redshift.Encryption{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
			EndPoint: redshift.EndPoint{
				Metadata: r.Metadata(),
				Port:     r.GetIntProperty("Endpoint.Port"),
			},
			SubnetGroupName: r.GetStringProperty("ClusterSubnetGroupName", ""),
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getParameters(ctx parser.FileContext) (parameter []redshift.ClusterParameter) {
	var parameters []redshift.ClusterParameter
	for _, r := range ctx.GetResourcesByType("AWS::Redshift::ClusterParameterGroup") {
		for _, par := range r.GetProperty("Parameters").AsList() {
			parameters = append(parameters, redshift.ClusterParameter{
				Metadata:       par.Metadata(),
				ParameterName:  par.GetStringProperty("ParameterName"),
				ParameterValue: par.GetStringProperty("ParameterValue"),
			})
		}
	}
	return parameters
}
