package compute

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/compute"
)

func adaptDisks(modules terraform.Modules) (disks []compute.Disk) {

	for _, diskBlock := range modules.GetResourcesByType("google_compute_disk") {
		disk := compute.Disk{
			Metadata: diskBlock.GetMetadata(),
			Name:     types.StringDefault("", diskBlock.GetMetadata()),
			Encryption: compute.DiskEncryption{
				Metadata:   diskBlock.GetMetadata(),
				RawKey:     types.BytesDefault(nil, diskBlock.GetMetadata()),
				KMSKeyLink: types.StringDefault("", diskBlock.GetMetadata()),
			},
		}
		if encBlock := diskBlock.GetBlock("disk_encryption_key"); encBlock.IsNotNil() {
			disk.Encryption.Metadata = encBlock.GetMetadata()
			disk.Encryption.KMSKeyLink = encBlock.GetAttribute("kms_key_self_link").AsStringValueOrDefault("", encBlock)
			disk.Encryption.RawKey = encBlock.GetAttribute("raw_key").AsBytesValueOrDefault(nil, encBlock)
		}
		disks = append(disks, disk)
	}

	return disks
}
