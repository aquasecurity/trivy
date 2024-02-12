package ecs

import (
	"encoding/json"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	Metadata defsecTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata                 defsecTypes.Metadata
	ContainerInsightsEnabled defsecTypes.BoolValue
}

type TaskDefinition struct {
	Metadata             defsecTypes.Metadata
	Volumes              []Volume
	ContainerDefinitions []ContainerDefinition
}

func CreateDefinitionsFromString(metadata defsecTypes.Metadata, str string) ([]ContainerDefinition, error) {
	var containerDefinitionsJSON []containerDefinitionJSON
	if err := json.Unmarshal([]byte(str), &containerDefinitionsJSON); err != nil {
		return nil, err
	}
	var definitions []ContainerDefinition
	for _, j := range containerDefinitionsJSON {
		definitions = append(definitions, j.convert(metadata))
	}
	return definitions, nil
}

// see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
type containerDefinitionJSON struct {
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	CPU          int               `json:"cpu"`
	Memory       int               `json:"memory"`
	Essential    bool              `json:"essential"`
	PortMappings []portMappingJSON `json:"portMappings"`
	EnvVars      []envVarJSON      `json:"environment"`
	Privileged   bool              `json:"privileged"`
}

type envVarJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type portMappingJSON struct {
	ContainerPort int `json:"containerPort"`
	HostPort      int `json:"hostPort"`
}

func (j containerDefinitionJSON) convert(metadata defsecTypes.Metadata) ContainerDefinition {
	var mappings []PortMapping
	for _, jMapping := range j.PortMappings {
		mappings = append(mappings, PortMapping{
			ContainerPort: defsecTypes.Int(jMapping.ContainerPort, metadata),
			HostPort:      defsecTypes.Int(jMapping.HostPort, metadata),
		})
	}
	var envVars []EnvVar
	for _, env := range j.EnvVars {
		envVars = append(envVars, EnvVar(env))
	}
	return ContainerDefinition{
		Metadata:     metadata,
		Name:         defsecTypes.String(j.Name, metadata),
		Image:        defsecTypes.String(j.Image, metadata),
		CPU:          defsecTypes.Int(j.CPU, metadata),
		Memory:       defsecTypes.Int(j.Memory, metadata),
		Essential:    defsecTypes.Bool(j.Essential, metadata),
		PortMappings: mappings,
		Environment:  envVars,
		Privileged:   defsecTypes.Bool(j.Privileged, metadata),
	}
}

type ContainerDefinition struct {
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	Image        defsecTypes.StringValue
	CPU          defsecTypes.IntValue
	Memory       defsecTypes.IntValue
	Essential    defsecTypes.BoolValue
	PortMappings []PortMapping
	Environment  []EnvVar
	Privileged   defsecTypes.BoolValue
}

type EnvVar struct {
	Name  string
	Value string
}

type PortMapping struct {
	ContainerPort defsecTypes.IntValue
	HostPort      defsecTypes.IntValue
}

type Volume struct {
	Metadata               defsecTypes.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	Metadata                 defsecTypes.Metadata
	TransitEncryptionEnabled defsecTypes.BoolValue
}
