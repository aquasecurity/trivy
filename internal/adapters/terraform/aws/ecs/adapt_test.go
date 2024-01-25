package ecs

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/providers/aws/ecs"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptClusterSettings(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.ClusterSettings
	}{
		{
			name: "container insights enabled",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"
			  
				setting {
				  name  = "containerInsights"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 defsecTypes.NewTestMisconfigMetadata(),
				ContainerInsightsEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
			},
		},
		{
			name: "invalid name",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"
			  
				setting {
				  name  = "invalidName"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 defsecTypes.NewTestMisconfigMetadata(),
				ContainerInsightsEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_cluster" "example" {			
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 defsecTypes.NewTestMisconfigMetadata(),
				ContainerInsightsEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptClusterSettings(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTaskDefinitionResource(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.TaskDefinition
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				family                = "service"
				container_definitions = <<EOF
[
	{
	"name": "my_service",
	"image": "my_image",
	"essential": true,
	"memory": 256,
	"cpu": 2,
	"environment": [
		{ "name": "ENVIRONMENT", "value": "development" }
	]
	}
]
				EOF
			  
				volume {
				  name = "service-storage"
			  
				  efs_volume_configuration {
					transit_encryption      = "ENABLED"
				  }
				}
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
							Metadata:                 defsecTypes.NewTestMisconfigMetadata(),
							TransitEncryptionEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
						},
					},
				},
				ContainerDefinitions: []ecs.ContainerDefinition{
					{
						Metadata:   defsecTypes.NewTestMisconfigMetadata(),
						Name:       defsecTypes.String("my_service", defsecTypes.NewTestMisconfigMetadata()),
						Image:      defsecTypes.String("my_image", defsecTypes.NewTestMisconfigMetadata()),
						CPU:        defsecTypes.Int(2, defsecTypes.NewTestMisconfigMetadata()),
						Memory:     defsecTypes.Int(256, defsecTypes.NewTestMisconfigMetadata()),
						Essential:  defsecTypes.Bool(true, defsecTypes.NewTestMisconfigMetadata()),
						Privileged: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						Environment: []ecs.EnvVar{
							{
								Name:  "ENVIRONMENT",
								Value: "development",
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				volume {
					name = "service-storage"
				
					efs_volume_configuration {
					}
				  }
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: defsecTypes.NewTestMisconfigMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: defsecTypes.NewTestMisconfigMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{

							Metadata:                 defsecTypes.NewTestMisconfigMetadata(),
							TransitEncryptionEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMisconfigMetadata()),
						},
					},
				},
				ContainerDefinitions: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTaskDefinitionResource(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_ecs_cluster" "example" {
		name = "services-cluster"
	  
		setting {
		  name  = "containerInsights"
		  value = "enabled"
		}
	}

	resource "aws_ecs_task_definition" "example" {
		family                = "service"
		container_definitions = <<EOF
	[
		{
			"name": "my_service",
			"essential": true,
			"memory": 256,
			"environment": [
				{ "name": "ENVIRONMENT", "value": "development" }
			]
		}
	]
		EOF
	  
		volume {
		  name = "service-storage"
	  
		  efs_volume_configuration {
			transit_encryption      = "ENABLED"
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.TaskDefinitions, 1)

	cluster := adapted.Clusters[0]
	taskDefinition := adapted.TaskDefinitions[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 9, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 5, cluster.Settings.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, cluster.Settings.Metadata.Range().GetEndLine())

	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, taskDefinition.Metadata.Range().GetStartLine())
	assert.Equal(t, 33, taskDefinition.Metadata.Range().GetEndLine())

	assert.Equal(t, 26, taskDefinition.Volumes[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 32, taskDefinition.Volumes[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 29, taskDefinition.Volumes[0].EFSVolumeConfiguration.Metadata.Range().GetStartLine())
	assert.Equal(t, 31, taskDefinition.Volumes[0].EFSVolumeConfiguration.Metadata.Range().GetEndLine())

	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())
}
