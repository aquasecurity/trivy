package ecs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getTaskDefinitions(ctx parser.FileContext) (taskDefinitions []ecs.TaskDefinition) {

	taskDefResources := ctx.GetResourcesByType("AWS::ECS::TaskDefinition")

	for _, r := range taskDefResources {
		definitions, _ := getContainerDefinitions(r)
		taskDef := ecs.TaskDefinition{
			Metadata:             r.Metadata(),
			Volumes:              getVolumes(r),
			ContainerDefinitions: definitions,
		}
		taskDefinitions = append(taskDefinitions, taskDef)
	}

	return taskDefinitions
}

func getContainerDefinitions(r *parser.Resource) ([]ecs.ContainerDefinition, error) {
	var definitions []ecs.ContainerDefinition
	containerDefs := r.GetProperty("ContainerDefinitions")
	if containerDefs.IsNil() || containerDefs.IsNotList() {
		return definitions, nil
	}
	for _, containerDef := range containerDefs.AsList() {

		var envVars []ecs.EnvVar
		envVarsList := containerDef.GetProperty("Environment")
		if envVarsList.IsNotNil() && envVarsList.IsList() {
			for _, envVar := range envVarsList.AsList() {
				envVars = append(envVars, ecs.EnvVar{
					Name:  envVar.GetStringProperty("Name"),
					Value: envVar.GetStringProperty("Value"),
				})
			}
		}
		definition := ecs.ContainerDefinition{
			Metadata:     containerDef.Metadata(),
			Name:         containerDef.GetStringProperty("Name"),
			Image:        containerDef.GetStringProperty("Image"),
			CPU:          containerDef.GetStringProperty("Cpu"),
			Memory:       containerDef.GetStringProperty("Memory"),
			Essential:    containerDef.GetBoolProperty("Essential"),
			Privileged:   containerDef.GetBoolProperty("Privileged"),
			Environment:  envVars,
			PortMappings: nil,
		}
		definitions = append(definitions, definition)
	}
	if containerDefs.IsNotNil() && containerDefs.IsString() {
		return ecs.CreateDefinitionsFromString(r.Metadata(), containerDefs.AsString())
	}
	return definitions, nil
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
