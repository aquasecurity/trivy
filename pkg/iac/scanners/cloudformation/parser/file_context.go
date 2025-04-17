package parser

import (
	"errors"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
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
	Ignores      ignore.Rules
	Parameters   map[string]*Parameter
	Resources    map[string]*Resource
	Mappings     map[string]any
	Conditions   map[string]Property
}

func (t *FileContext) Validate() error {
	if len(t.Resources) == 0 {
		return errors.New("no resources found")
	}

	return nil
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

// TODO: use map[string]string
func (t *FileContext) overrideParameters(params map[string]any) {
	for key := range t.Parameters {
		if val, ok := params[key]; ok {
			t.Parameters[key].UpdateDefault(val)
		}
	}
}

func (t *FileContext) missingParameterValues() []string {
	var missing []string
	for key := range t.Parameters {
		if t.Parameters[key].Default == nil {
			missing = append(missing, key)
		}
	}
	return missing
}
