package workspaces

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/aws/workspaces"
)

func Adapt(modules terraform.Modules) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules terraform.Modules) []workspaces.WorkSpace {
	var workspaces []workspaces.WorkSpace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_workspaces_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource *terraform.Block) workspaces.WorkSpace {
	rootVolumeEncryptAttr := resource.GetAttribute("root_volume_encryption_enabled")
	rootVolumeEncryptVal := rootVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	userVolumeEncryptAttr := resource.GetAttribute("user_volume_encryption_enabled")
	userVolumeEncryptVal := userVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)

	return workspaces.WorkSpace{
		Metadata: resource.GetMetadata(),
		RootVolume: workspaces.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  rootVolumeEncryptVal,
			},
		},
		UserVolume: workspaces.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  userVolumeEncryptVal,
			},
		},
	}
}
