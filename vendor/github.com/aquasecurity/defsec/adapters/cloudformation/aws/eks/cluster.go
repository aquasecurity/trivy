package eks

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/eks"
)

func getClusters(ctx parser.FileContext) (clusters []eks.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::EKS::Cluster")

	for _, r := range clusterResources {
		cluster := eks.Cluster{
			Metadata: r.Metadata(),
			// Logging not supported for cloudformation https://github.com/aws/containers-roadmap/issues/242
			Logging:    eks.Logging{},
			Encryption: getEncryptionConfig(r),
			// endpoint protection not supported - https://github.com/aws/containers-roadmap/issues/242
			PublicAccessEnabled: nil,
			PublicAccessCIDRs:   nil,
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getEncryptionConfig(r *parser.Resource) eks.Encryption {

	encryption := eks.Encryption{
		Secrets:  types.BoolDefault(false, r.Metadata()),
		KMSKeyID: types.StringDefault("", r.Metadata()),
	}

	resourcesProp := r.GetProperty("EncryptionConfig.Resources")
	if resourcesProp.IsList() {
		if resourcesProp.Contains("secrets") {
			encryption.Secrets = types.Bool(true, resourcesProp.Metadata())
		}
	}

	encryption.KMSKeyID = r.GetStringProperty("EncryptionConfig.Provider.KeyArn")

	return encryption
}
