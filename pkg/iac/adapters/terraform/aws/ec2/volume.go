package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptVolumes(modules terraform.Modules) []ec2.Volume {
	var volumes []ec2.Volume
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_volume") {
			volumes = append(volumes, adaptVolume(resource, module))
		}
	}
	return volumes
}

func adaptVolume(resource *terraform.Block, module *terraform.Module) ec2.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValue()

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValue()

	if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(kmsKeyAttr, resource); err == nil {
			kmsKeyVal = types.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	return ec2.Volume{
		Metadata: resource.GetMetadata(),
		Encryption: ec2.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
