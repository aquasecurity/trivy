package eks

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClusters(ctx parser2.FileContext) (clusters []eks.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::EKS::Cluster")

	for _, r := range clusterResources {
		cluster := eks.Cluster{
			Metadata: r.Metadata(),
			// Logging not supported for cloudformation https://github.com/aws/containers-roadmap/issues/242
			Logging: eks.Logging{
				Metadata:          r.Metadata(),
				API:               iacTypes.BoolUnresolvable(r.Metadata()),
				Audit:             iacTypes.BoolUnresolvable(r.Metadata()),
				Authenticator:     iacTypes.BoolUnresolvable(r.Metadata()),
				ControllerManager: iacTypes.BoolUnresolvable(r.Metadata()),
				Scheduler:         iacTypes.BoolUnresolvable(r.Metadata()),
			},
			Encryption: getEncryptionConfig(r),
			// endpoint protection not supported - https://github.com/aws/containers-roadmap/issues/242
			PublicAccessEnabled: iacTypes.BoolUnresolvable(r.Metadata()),
			PublicAccessCIDRs:   nil,
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getEncryptionConfig(r *parser2.Resource) eks.Encryption {

	encryption := eks.Encryption{
		Metadata: r.Metadata(),
		Secrets:  iacTypes.BoolDefault(false, r.Metadata()),
		KMSKeyID: iacTypes.StringDefault("", r.Metadata()),
	}

	if encProp := r.GetProperty("EncryptionConfig"); encProp.IsNotNil() {
		encryption.Metadata = encProp.Metadata()
		encryption.KMSKeyID = encProp.GetStringProperty("Provider.KeyArn")
		resourcesProp := encProp.GetProperty("Resources")
		if resourcesProp.IsList() {
			if resourcesProp.Contains("secrets") {
				encryption.Secrets = iacTypes.Bool(true, resourcesProp.Metadata())
			}
		}
	}

	return encryption
}
