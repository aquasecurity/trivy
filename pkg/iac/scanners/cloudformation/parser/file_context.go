package parser

import (
	"fmt"
	"maps"
	"regexp"
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SourceFormat string

const (
	YamlSourceFormat SourceFormat = "yaml"
	JsonSourceFormat SourceFormat = "json"

	ForEachPrefix = "Fn::ForEach::"
)

type FileContexts []*FileContext

type FileContext struct {
	filepath     string
	lines        []string
	SourceFormat SourceFormat
	Ignores      ignore.Rules
	Parameters   map[string]*Parameter `json:"Parameters" yaml:"Parameters"`
	Resources    map[string]*Resource  `json:"Resources" yaml:"Resources"`
	Globals      map[string]*Resource  `json:"Globals" yaml:"Globals"`
	Mappings     map[string]any        `json:"Mappings,omitempty" yaml:"Mappings"`
	Conditions   map[string]Property   `json:"Conditions,omitempty" yaml:"Conditions"`
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
		if t.Parameters[key].inner.Default == nil {
			missing = append(missing, key)
		}
	}
	return missing
}

func (t *FileContext) stripNullProperties() {
	for _, resource := range t.Resources {
		resource.properties = lo.OmitBy(resource.properties, func(_ string, v *Property) bool {
			return v.IsNil()
		})
	}
}

func (t *FileContext) expandTransforms() error {
	resources := make(map[string]*Resource, len(t.Resources))

	for name, r := range t.Resources {
		if r.raw == nil {
			resources[name] = r
			continue
		}

		instances, err := t.expandTransform(r.raw, name)
		if err != nil {
			return err
		}

		for logicalID, rawProp := range instances {
			instance, err := newExpandedResource(r, logicalID, rawProp)
			if err != nil {
				return err
			}
			resources[logicalID] = instance
		}
	}

	t.Resources = resources
	return nil
}

func newExpandedResource(base *Resource, logicalID string, raw *Property) (*Resource, error) {
	rawMap := raw.AsMap()
	typProp, ok := rawMap["Type"]
	if !ok {
		return nil, fmt.Errorf("missing 'Type' in expanded resource %q", logicalID)
	}
	propsProp, ok := rawMap["Properties"]
	if !ok {
		return nil, fmt.Errorf("missing 'Properties' in expanded resource %q", logicalID)
	}

	instance := base.clone()
	instance.typ = typProp.AsString()
	instance.properties = propsProp.AsMap()
	instance.setId(logicalID)
	return instance, nil
}

func (t *FileContext) expandTransform(prop *Property, logicalName string) (map[string]*Property, error) {
	if strings.HasPrefix(logicalName, "Fn::ForEach::") {
		return expandForEach(prop, nil)
	}

	return nil, nil
}

func expandForEach(prop *Property, parentCtx *LoopContext) (map[string]*Property, error) {

	args := prop.AsList()
	if len(args) != 3 {
		return nil, fmt.Errorf("invalid Fn::ForEach: expected 3 arguments, got %d", len(args))
	}

	identifier := args[0].AsString()
	coll := args[1].AsList()
	templ := args[2].AsMap()

	result := make(map[string]*Property)

	for _, el := range coll {
		loopCtx := parentCtx.Child(identifier, el)

		for tmplKey, templValue := range templ {
			cp := templValue.clone()

			// handle nested loop
			if strings.HasPrefix(tmplKey, ForEachPrefix) {
				nestedResult, err := expandForEach(cp, loopCtx)
				if err != nil {
					return nil, err
				}
				maps.Copy(result, nestedResult)
				continue
			}

			logicalID := resolveLoopPlaceholders(tmplKey, loopCtx)
			cp.setLogicalResource(logicalID)
			if err := expandProperties(cp, loopCtx); err != nil {
				return nil, err
			}

			result[logicalID] = cp
		}
	}

	return result, nil
}

var placeholderRe = regexp.MustCompile(`[$&]\{([^}]+)\}`)

func resolveLoopPlaceholders(v string, loopCtx *LoopContext) string {
	return placeholderRe.ReplaceAllStringFunc(v, func(s string) string {
		id := s[2 : len(s)-1]
		val, found := loopCtx.Resolve(id)
		if found {
			return val.AsString()
		}
		return s
	})
}

func expandProperties(prop *Property, parentCtx *LoopContext) error {
	prop.loopCtx = parentCtx

	switch v := prop.Value.(type) {
	case string:
		prop.Value = resolveLoopPlaceholders(v, parentCtx)
	case map[string]*Property:
		newProps := make(map[string]*Property)
		for k, el := range v {
			if strings.HasPrefix(k, ForEachPrefix) {
				expanded, err := expandForEach(el, parentCtx)
				if err != nil {
					return err
				}
				maps.Copy(newProps, expanded)
			} else {
				if err := expandProperties(el, parentCtx); err != nil {
					return err
				}
				newProps[k] = el
			}
		}
		prop.Value = newProps
	case []*Property:
		for _, el := range v {
			if err := expandProperties(el, parentCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

type LoopContext struct {
	Identifier string
	Value      *Property
	Parent     *LoopContext
}

func (c *LoopContext) Child(identifier string, value *Property) *LoopContext {
	return &LoopContext{
		Identifier: identifier,
		Value:      value,
		Parent:     c,
	}
}

func (c *LoopContext) Resolve(name string) (*Property, bool) {
	if c.Identifier == name {
		return c.Value, true
	}
	if c.Parent != nil {
		return c.Parent.Resolve(name)
	}
	return nil, false
}
