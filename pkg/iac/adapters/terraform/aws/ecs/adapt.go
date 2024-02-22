package ecs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) ecs.ECS {
	return ecs.ECS{
		Clusters:        adaptClusters(modules),
		TaskDefinitions: adaptTaskDefinitions(modules),
	}
}

func adaptClusters(modules terraform.Modules) []ecs.Cluster {
	var clusters []ecs.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_cluster") {
			clusters = append(clusters, adaptClusterResource(resource))
		}
	}
	return clusters
}

func adaptClusterResource(resourceBlock *terraform.Block) ecs.Cluster {
	return ecs.Cluster{
		Metadata: resourceBlock.GetMetadata(),
		Settings: adaptClusterSettings(resourceBlock),
	}
}

func adaptClusterSettings(resourceBlock *terraform.Block) ecs.ClusterSettings {
	settings := ecs.ClusterSettings{
		Metadata:                 resourceBlock.GetMetadata(),
		ContainerInsightsEnabled: types.BoolDefault(false, resourceBlock.GetMetadata()),
	}

	if settingBlock := resourceBlock.GetBlock("setting"); settingBlock.IsNotNil() {
		settings.Metadata = settingBlock.GetMetadata()
		if settingBlock.GetAttribute("name").Equals("containerInsights") {
			insightsAttr := settingBlock.GetAttribute("value")
			settings.ContainerInsightsEnabled = types.Bool(insightsAttr.Equals("enabled"), settingBlock.GetMetadata())
			if insightsAttr.IsNotNil() {
				settings.ContainerInsightsEnabled = types.Bool(insightsAttr.Equals("enabled"), insightsAttr.GetMetadata())
			}
		}
	}
	return settings
}

func adaptTaskDefinitions(modules terraform.Modules) []ecs.TaskDefinition {
	var taskDefinitions []ecs.TaskDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_task_definition") {
			taskDefinitions = append(taskDefinitions, adaptTaskDefinitionResource(resource))
		}
	}
	return taskDefinitions
}

func adaptTaskDefinitionResource(resourceBlock *terraform.Block) ecs.TaskDefinition {

	var definitions []ecs.ContainerDefinition
	if ct := resourceBlock.GetAttribute("container_definitions"); ct != nil && ct.IsString() {
		definitions, _ = ecs.CreateDefinitionsFromString(resourceBlock.GetMetadata(), ct.Value().AsString())
	}

	return ecs.TaskDefinition{
		Metadata:             resourceBlock.GetMetadata(),
		Volumes:              adaptVolumes(resourceBlock),
		ContainerDefinitions: definitions,
	}
}

func adaptVolumes(resourceBlock *terraform.Block) []ecs.Volume {
	if volumeBlocks := resourceBlock.GetBlocks("volume"); len(volumeBlocks) > 0 {
		var volumes []ecs.Volume
		for _, volumeBlock := range volumeBlocks {
			volumes = append(volumes, ecs.Volume{
				Metadata:               volumeBlock.GetMetadata(),
				EFSVolumeConfiguration: adaptEFSVolumeConfiguration(volumeBlock),
			})
		}
		return volumes
	}

	return []ecs.Volume{}
}

func adaptEFSVolumeConfiguration(volumeBlock *terraform.Block) ecs.EFSVolumeConfiguration {
	EFSVolumeConfiguration := ecs.EFSVolumeConfiguration{
		Metadata:                 volumeBlock.GetMetadata(),
		TransitEncryptionEnabled: types.BoolDefault(true, volumeBlock.GetMetadata()),
	}

	if EFSConfigBlock := volumeBlock.GetBlock("efs_volume_configuration"); EFSConfigBlock.IsNotNil() {
		EFSVolumeConfiguration.Metadata = EFSConfigBlock.GetMetadata()
		transitEncryptionAttr := EFSConfigBlock.GetAttribute("transit_encryption")
		EFSVolumeConfiguration.TransitEncryptionEnabled = types.Bool(transitEncryptionAttr.Equals("ENABLED"), EFSConfigBlock.GetMetadata())
		if transitEncryptionAttr.IsNotNil() {
			EFSVolumeConfiguration.TransitEncryptionEnabled = types.Bool(transitEncryptionAttr.Equals("ENABLED"), transitEncryptionAttr.GetMetadata())
		}
	}

	return EFSVolumeConfiguration
}
