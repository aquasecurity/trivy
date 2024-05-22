package efs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/efs"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) efs.EFS {
	return efs.EFS{
		FileSystems: adaptFileSystems(modules),
	}
}

func adaptFileSystems(modules terraform.Modules) []efs.FileSystem {
	var filesystems []efs.FileSystem
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_efs_file_system") {
			filesystems = append(filesystems, adaptFileSystem(resource))
		}
	}
	return filesystems
}

func adaptFileSystem(resource *terraform.Block) efs.FileSystem {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	return efs.FileSystem{
		Metadata:  resource.GetMetadata(),
		Encrypted: encryptedVal,
	}
}
