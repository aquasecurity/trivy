package ecs

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/ecs"
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

	if settingBlock := resourceBlock.GetBlock("setting"); settingBlock.IsNotNil() && settingBlock.GetAttribute("name").Equals("containerInsights") {
		containerInsightsEnabled := settingBlock.GetAttribute("value").Equals("enabled")
		settings.ContainerInsightsEnabled = types.Bool(containerInsightsEnabled, settingBlock.GetMetadata())
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
	return ecs.TaskDefinition{
		Metadata:             resourceBlock.GetMetadata(),
		Volumes:              adaptVolumes(resourceBlock),
		ContainerDefinitions: resourceBlock.GetAttribute("container_definitions").AsStringValueOrDefault("", resourceBlock),
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
	if EFSConfigBlock := volumeBlock.GetBlock("efs_volume_configuration"); EFSConfigBlock.IsNotNil() {
		transitEncryptionEnabled := EFSConfigBlock.GetAttribute("transit_encryption").Equals("ENABLED")
		return ecs.EFSVolumeConfiguration{
			Metadata:                 EFSConfigBlock.GetMetadata(),
			TransitEncryptionEnabled: types.Bool(transitEncryptionEnabled, EFSConfigBlock.GetMetadata()),
		}
	}

	return ecs.EFSVolumeConfiguration{
		Metadata:                 volumeBlock.GetMetadata(),
		TransitEncryptionEnabled: types.BoolDefault(true, volumeBlock.GetMetadata()),
	}
}
