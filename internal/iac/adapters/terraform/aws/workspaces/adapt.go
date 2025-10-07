package workspaces

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/workspaces"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules terraform.Modules) []workspaces.WorkSpace {
	var ws []workspaces.WorkSpace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_workspaces_workspace") {
			ws = append(ws, adaptWorkspace(resource))
		}
	}
	return ws
}

func adaptWorkspace(resource *terraform.Block) workspaces.WorkSpace {

	workspace := workspaces.WorkSpace{
		Metadata: resource.GetMetadata(),
		RootVolume: workspaces.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
		},
		UserVolume: workspaces.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
		},
	}
	if rootVolumeEncryptAttr := resource.GetAttribute("root_volume_encryption_enabled"); rootVolumeEncryptAttr.IsNotNil() {
		workspace.RootVolume.Metadata = rootVolumeEncryptAttr.GetMetadata()
		workspace.RootVolume.Encryption.Metadata = rootVolumeEncryptAttr.GetMetadata()
		workspace.RootVolume.Encryption.Enabled = rootVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)
	}

	if userVolumeEncryptAttr := resource.GetAttribute("user_volume_encryption_enabled"); userVolumeEncryptAttr.IsNotNil() {
		workspace.UserVolume.Metadata = userVolumeEncryptAttr.GetMetadata()
		workspace.UserVolume.Encryption.Metadata = userVolumeEncryptAttr.GetMetadata()
		workspace.UserVolume.Encryption.Enabled = userVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)
	}

	return workspace
}
