package parser

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"strings"

	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type Resource struct {
	xjson.Location
	typ        string
	properties map[string]*Property
	ctx        *FileContext
	rng        iacTypes.Range
	id         string
	comment    string

	raw *Property
}

func (r *Resource) configureResource(id string, target fs.FS, filepath string, ctx *FileContext) {
	r.setId(id)
	r.setFile(target, filepath)
	r.setContext(ctx)
}

func (r *Resource) setId(id string) {
	r.id = id

	for n, p := range r.properties {
		p.setName(n)
	}
}

func (r *Resource) setFile(target fs.FS, filepath string) {
	r.rng = iacTypes.NewRange(filepath, r.StartLine, r.EndLine, r.rng.GetSourcePrefix(), target)

	for _, p := range r.properties {
		p.setFileAndParentRange(target, filepath, r.rng)
	}
}

func (r *Resource) setContext(ctx *FileContext) {
	r.ctx = ctx
	if r.raw != nil {
		r.raw.setContext(ctx)
	} else {
		for _, p := range r.properties {
			p.setLogicalResource(r.id)
			p.setContext(ctx)
		}
	}
}

func (r *Resource) clone() *Resource {
	clone := &Resource{
		typ:     r.typ,
		ctx:     r.ctx,
		rng:     r.rng,
		id:      r.id,
		comment: r.comment,
	}

	if r.properties != nil {
		clone.properties = make(map[string]*Property, len(r.properties))
		for k, p := range r.properties {
			clone.properties[k] = p.clone()
		}
	}

	if r.raw != nil {
		clone.raw = r.raw.clone()
	}

	return clone
}

type resourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) UnmarshalYAML(node *yaml.Node) error {
	r.StartLine = node.Line - 1
	r.EndLine = calculateEndLine(node)
	r.comment = node.LineComment

	switch node.Kind {
	case yaml.MappingNode:
		var i resourceInner
		if err := node.Decode(&i); err != nil {
			return err
		}
		r.typ = i.Type
		r.properties = i.Properties
		return nil
	case yaml.SequenceNode:
		var raw Property
		if err := node.Decode(&raw); err != nil {
			return err
		}
		r.raw = &raw
		return nil
	default:
		return fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func (r *Resource) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch dec.PeekKind() {
	case '{':
		var i resourceInner
		if err := json.UnmarshalDecode(dec, &i); err != nil {
			return err
		}
		r.typ = i.Type
		r.properties = i.Properties
	case '[':
		var raw Property
		if err := json.UnmarshalDecode(dec, &raw); err != nil {
			return err
		}
		r.raw = &raw
	}
	return nil
}

func (r *Resource) ID() string {
	return r.id
}

func (r *Resource) Type() string {
	return r.typ
}

func (r *Resource) Range() iacTypes.Range {
	return r.rng
}

func (r *Resource) SourceFormat() SourceFormat {
	return r.ctx.SourceFormat
}

func (r *Resource) Metadata() iacTypes.Metadata {
	return iacTypes.NewMetadata(r.Range(), NewCFReference(r.id, r.rng).String())
}

func (r *Resource) IsNil() bool {
	return r.id == ""
}

func (r *Resource) nullProperty() *Property {
	return &Property{rng: r.rng, logicalId: r.id}
}

func (r *Resource) GetProperty(path string) *Property {
	parts := strings.Split(path, ".")

	first := parts[0]

	p, exists := r.properties[first]
	if !exists {
		return r.nullProperty()
	}

	if len(parts) == 1 {
		if p.isFunction() {
			resolved, _ := p.resolveValue()
			return resolved
		}
		return p
	}

	return p.GetProperty(strings.Join(parts[1:], "."))
}

func (r *Resource) GetStringProperty(path string, defaultValue ...string) iacTypes.StringValue {
	return r.GetProperty(path).AsStringValue(firstOrZero(defaultValue))
}

func (r *Resource) GetBoolProperty(path string, defaultValue ...bool) iacTypes.BoolValue {
	return r.GetProperty(path).AsBoolValue(firstOrZero(defaultValue))
}

func (r *Resource) GetIntProperty(path string, defaultValue ...int) iacTypes.IntValue {
	return r.GetProperty(path).AsIntValue(firstOrZero(defaultValue))
}

func (r *Resource) StringDefault(defaultValue string) iacTypes.StringValue {
	return iacTypes.StringDefault(defaultValue, r.Metadata())
}

func (r *Resource) BoolDefault(defaultValue bool) iacTypes.BoolValue {
	return iacTypes.BoolDefault(defaultValue, r.Metadata())
}

func (r *Resource) IntDefault(defaultValue int) iacTypes.IntValue {
	return iacTypes.IntDefault(defaultValue, r.Metadata())
}
