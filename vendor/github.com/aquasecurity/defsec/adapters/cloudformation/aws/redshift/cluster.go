package redshift

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/redshift"
)

func getClusters(ctx parser.FileContext) (clusters []redshift.Cluster) {
	for _, r := range ctx.GetResourcesByType("AWS::Redshift::Cluster") {

		cluster := redshift.Cluster{
			Metadata: r.Metadata(),
			Encryption: redshift.Encryption{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
			SubnetGroupName: r.GetStringProperty("ClusterSubnetGroupName", ""),
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}
