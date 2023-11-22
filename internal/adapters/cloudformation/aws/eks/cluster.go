package eks

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

func getClusters(ctx parser.FileContext) (clusters []eks.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::EKS::Cluster")

	for _, r := range clusterResources {
		cluster := eks.Cluster{
			Metadata: r.Metadata(),
			// Logging not supported for cloudformation https://github.com/aws/containers-roadmap/issues/242
			Logging: eks.Logging{
				Metadata:          r.Metadata(),
				API:               defsecTypes.BoolUnresolvable(r.Metadata()),
				Audit:             defsecTypes.BoolUnresolvable(r.Metadata()),
				Authenticator:     defsecTypes.BoolUnresolvable(r.Metadata()),
				ControllerManager: defsecTypes.BoolUnresolvable(r.Metadata()),
				Scheduler:         defsecTypes.BoolUnresolvable(r.Metadata()),
			},
			Encryption: getEncryptionConfig(r),
			// endpoint protection not supported - https://github.com/aws/containers-roadmap/issues/242
			PublicAccessEnabled: defsecTypes.BoolUnresolvable(r.Metadata()),
			PublicAccessCIDRs:   nil,
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getEncryptionConfig(r *parser.Resource) eks.Encryption {

	encryption := eks.Encryption{
		Metadata: r.Metadata(),
		Secrets:  defsecTypes.BoolDefault(false, r.Metadata()),
		KMSKeyID: defsecTypes.StringDefault("", r.Metadata()),
	}

	if encProp := r.GetProperty("EncryptionConfig"); encProp.IsNotNil() {
		encryption.Metadata = encProp.Metadata()
		encryption.KMSKeyID = encProp.GetStringProperty("Provider.KeyArn")
		resourcesProp := encProp.GetProperty("Resources")
		if resourcesProp.IsList() {
			if resourcesProp.Contains("secrets") {
				encryption.Secrets = defsecTypes.Bool(true, resourcesProp.Metadata())
			}
		}
	}

	return encryption
}
