package parser

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SourceFormat string

const (
	YamlSourceFormat SourceFormat = "yaml"
	JsonSourceFormat SourceFormat = "json"
)

type FileContexts []*FileContext

type FileContext struct {
	filepath     string
	lines        []string
	SourceFormat SourceFormat
	Parameters   map[string]*Parameter  `json:"Parameters" yaml:"Parameters"`
	Resources    map[string]*Resource   `json:"Resources" yaml:"Resources"`
	Globals      map[string]*Resource   `json:"Globals" yaml:"Globals"`
	Mappings     map[string]interface{} `json:"Mappings,omitempty" yaml:"Mappings"`
	Conditions   map[string]Property    `json:"Conditions,omitempty" yaml:"Conditions"`
}

func (t *FileContext) GetResourceByLogicalID(name string) *Resource {
	for n, r := range t.Resources {
		if name == n {
			return r
		}
	}
	return nil
}

func (t *FileContext) GetResourcesByType(names ...string) []*Resource {
	var resources []*Resource
	for _, r := range t.Resources {
		for _, name := range names {
			if name == r.Type() {
				//
				resources = append(resources, r)
			}
		}
	}
	return resources
}

func (t *FileContext) Metadata() iacTypes.Metadata {
	rng := iacTypes.NewRange(t.filepath, 1, len(t.lines), "", nil)

	return iacTypes.NewMetadata(rng, NewCFReference("Template", rng).String())
}

func (t *FileContext) OverrideParameters(params map[string]any) {
	for key := range t.Parameters {
		if val, ok := params[key]; ok {
			t.Parameters[key].UpdateDefault(val)
		}
	}
}
