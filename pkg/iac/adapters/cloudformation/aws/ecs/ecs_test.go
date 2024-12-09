package ecs

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ecs.ECS
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ECSCluster:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyFargateCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
  taskdefinition: 
    Type: AWS::ECS::TaskDefinition
    Properties: 
      ContainerDefinitions: 
        - 
          Name: "busybox"
          Image: "busybox"
          Cpu: "256"
          Memory: "512"
          Essential: true
          Privileged: true
          Environment:
            - Name: entryPoint
              Value: 'sh, -c'
      Volumes: 
        - 
          Host: 
            SourcePath: "/var/lib/docker/vfs/dir/"
          Name: "my-vol"
          EFSVolumeConfiguration:
            TransitEncryption: enabled
`,
			expected: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Settings: ecs.ClusterSettings{
							ContainerInsightsEnabled: types.BoolTest(true),
						},
					},
				},
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Volumes: []ecs.Volume{
							{
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									TransitEncryptionEnabled: types.BoolTest(true),
								},
							},
						},
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Name:       types.StringTest("busybox"),
								Image:      types.StringTest("busybox"),
								CPU:        types.StringTest("256"),
								Memory:     types.StringTest("512"),
								Essential:  types.BoolTest(true),
								Privileged: types.BoolTest(true),
								Environment: []ecs.EnvVar{
									{
										Name:  types.StringTest("entryPoint"),
										Value: types.StringTest("sh, -c"),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  ECSCluster:
    Type: 'AWS::ECS::Cluster'
  taskdefinition: 
    Type: AWS::ECS::TaskDefinition
  `,
			expected: ecs.ECS{
				Clusters:        []ecs.Cluster{{}},
				TaskDefinitions: []ecs.TaskDefinition{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
