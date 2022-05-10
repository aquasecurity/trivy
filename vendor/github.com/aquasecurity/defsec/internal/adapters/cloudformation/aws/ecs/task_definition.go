package ecs

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getTaskDefinitions(ctx parser.FileContext) (taskDefinitions []ecs.TaskDefinition) {

	taskDefResources := ctx.GetResourcesByType("AWS::ECS::TaskDefinition")

	for _, r := range taskDefResources {
		taskDef := ecs.TaskDefinition{
			Metadata:             r.Metadata(),
			Volumes:              getVolumes(r),
			ContainerDefinitions: getContainerDefinitions(r),
		}

		taskDefinitions = append(taskDefinitions, taskDef)
	}

	return taskDefinitions
}

func getContainerDefinitions(r *parser.Resource) types.StringValue {
	containerDefs := r.GetProperty("ContainerDefinitions")
	if containerDefs.IsNil() || containerDefs.IsNotList() {
		return types.StringDefault("", r.Metadata())
	}

	return types.String(containerDefs.GetJsonBytesAsString(), containerDefs.Metadata())
}

func getVolumes(r *parser.Resource) (volumes []ecs.Volume) {

	volumesList := r.GetProperty("Volumes")
	if volumesList.IsNil() || volumesList.IsNotList() {
		return volumes
	}

	for _, v := range volumesList.AsList() {
		volume := ecs.Volume{
			Metadata: r.Metadata(),
			EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
				Metadata:                 r.Metadata(),
				TransitEncryptionEnabled: types.BoolDefault(false, r.Metadata()),
			},
		}
		transitProp := v.GetProperty("EFSVolumeConfiguration.TransitEncryption")
		if transitProp.IsNotNil() && transitProp.EqualTo("enabled", parser.IgnoreCase) {
			volume.EFSVolumeConfiguration.TransitEncryptionEnabled = types.Bool(true, transitProp.Metadata())
		}

		volumes = append(volumes, volume)
	}
	return volumes
}
