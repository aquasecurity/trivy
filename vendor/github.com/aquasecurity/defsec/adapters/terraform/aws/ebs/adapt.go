package ebs

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
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
			volumes = append(volumes, adaptVolume(resource, module))
		}
	}
	return volumes
}

func adaptVolume(resource *terraform.Block, module *terraform.Module) ebs.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValueOrDefault("", resource)

	if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(kmsKeyAttr, resource); err == nil {
			kmsKeyVal = types.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	return ebs.Volume{
		Metadata: resource.GetMetadata(),
		Encryption: ebs.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
