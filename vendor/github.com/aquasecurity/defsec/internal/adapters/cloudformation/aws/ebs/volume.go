package ebs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ebs"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getVolumes(ctx parser.FileContext) (volumes []ebs.Volume) {

	volumeResources := ctx.GetResourcesByType("AWS::EC2::Volume")
	for _, r := range volumeResources {

		volume := ebs.Volume{
			Metadata: r.Metadata(),
			Encryption: ebs.Encryption{
				Metadata: r.Metadata(),
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
		}

		volumes = append(volumes, volume)
	}
	return volumes
}
