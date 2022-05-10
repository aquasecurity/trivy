package compute

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/compute"
)

func adaptDisks(modules terraform.Modules) (disks []compute.Disk) {

	for _, diskBlock := range modules.GetResourcesByType("google_compute_disk") {
		var disk compute.Disk
		disk.Metadata = diskBlock.GetMetadata()
		if encBlock := diskBlock.GetBlock("disk_encryption_key"); encBlock.IsNotNil() {
			disk.Encryption.KMSKeyLink = encBlock.GetAttribute("kms_key_self_link").AsStringValueOrDefault("", encBlock)
			disk.Encryption.RawKey = encBlock.GetAttribute("raw_key").AsBytesValueOrDefault(nil, encBlock)
		} else {
			disk.Encryption.KMSKeyLink = types.StringDefault("", diskBlock.GetMetadata())
			disk.Encryption.RawKey = types.BytesDefault(nil, diskBlock.GetMetadata())
		}
		disks = append(disks, disk)
	}

	return disks
}
