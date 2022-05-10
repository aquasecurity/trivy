package ebs

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws/ebs"
)

func Adapt(modules terraform.Modules) ebs.EBS {
	return ebs.EBS{
		Volumes: adaptVolumes(modules),
	}
}

func adaptVolumes(modules terraform.Modules) []ebs.Volume {
	var volumes []ebs.Volume
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_volume") {
			volumes = append(volumes, adaptVolume(resource))
		}
	}
	return volumes
}

func adaptVolume(resource *terraform.Block) ebs.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValueOrDefault("", resource)

	return ebs.Volume{
		Metadata: resource.GetMetadata(),
		Encryption: ebs.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
