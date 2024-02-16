package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptDisks(modules terraform.Modules) (disks []compute.Disk) {

	for _, diskBlock := range modules.GetResourcesByType("google_compute_disk") {
		disk := compute.Disk{
			Metadata: diskBlock.GetMetadata(),
			Name:     diskBlock.GetAttribute("name").AsStringValueOrDefault("", diskBlock),
			Encryption: compute.DiskEncryption{
				Metadata:   diskBlock.GetMetadata(),
				RawKey:     iacTypes.BytesDefault(nil, diskBlock.GetMetadata()),
				KMSKeyLink: iacTypes.StringDefault("", diskBlock.GetMetadata()),
			},
		}
		if encBlock := diskBlock.GetBlock("disk_encryption_key"); encBlock.IsNotNil() {
			disk.Encryption.Metadata = encBlock.GetMetadata()
			kmsKeyAttr := encBlock.GetAttribute("kms_key_self_link")
			disk.Encryption.KMSKeyLink = kmsKeyAttr.AsStringValueOrDefault("", encBlock)

			if kmsKeyAttr.IsResourceBlockReference("google_kms_crypto_key") {
				if kmsKeyBlock, err := modules.GetReferencedBlock(kmsKeyAttr, encBlock); err == nil {
					disk.Encryption.KMSKeyLink = iacTypes.String(kmsKeyBlock.FullName(), kmsKeyAttr.GetMetadata())
				}
			}

			disk.Encryption.RawKey = encBlock.GetAttribute("raw_key").AsBytesValueOrDefault(nil, encBlock)
		}
		disks = append(disks, disk)
	}

	return disks
}
