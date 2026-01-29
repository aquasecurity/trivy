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

func (r *Resource) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := &Property{}

	if p, exists := r.properties[first]; exists {
		property = p
	}

	if len(pathParts) == 1 || property.IsNil() {
		if property.isFunction() {
			resolved, _ := property.resolveValue()
			return resolved
		}
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty
	}

	return &Property{}
}

func (r *Resource) GetStringProperty(path string, defaultValue ...string) iacTypes.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotString() {
		return r.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

func (r *Resource) GetBoolProperty(path string, defaultValue ...bool) iacTypes.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotBool() {
		return r.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

func (r *Resource) GetIntProperty(path string, defaultValue ...int) iacTypes.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotInt() {
		return r.IntDefault(defVal)
	}
	return prop.AsIntValue()
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

func (r *Resource) inferBool(prop *Property, defaultValue bool) iacTypes.BoolValue {
	if prop.IsString() {
		if prop.EqualTo("true", IgnoreCase) {
			return iacTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("yes", IgnoreCase) {
			return iacTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("1", IgnoreCase) {
			return iacTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("false", IgnoreCase) {
			return iacTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("no", IgnoreCase) {
			return iacTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("0", IgnoreCase) {
			return iacTypes.Bool(false, prop.Metadata())
		}
	}

	if prop.IsInt() {
		if prop.EqualTo(0) {
			return iacTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo(1) {
			return iacTypes.Bool(true, prop.Metadata())
		}
	}

	return r.BoolDefault(defaultValue)
}
