package parser

import (
	"encoding/json"
	"io/fs"
	"strconv"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type EqualityOptions = int

const (
	IgnoreCase EqualityOptions = iota
)

type Property struct {
	ctx         *FileContext
	name        string
	comment     string
	rng         iacTypes.Range
	parentRange iacTypes.Range
	Inner       PropertyInner
	logicalId   string
	unresolved  bool
}

type PropertyInner struct {
	Type  cftypes.CfType
	Value interface{} `json:"Value" yaml:"Value"`
}

func (p *Property) Comment() string {
	return p.comment
}

func (p *Property) setName(name string) {
	p.name = name
	if p.Type() == cftypes.Map {
		for n, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setName(n)
		}
	}
}

func (p *Property) setContext(ctx *FileContext) {
	p.ctx = ctx

	if p.IsMap() {
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setContext(ctx)
		}
	}

	if p.IsList() {
		for _, subProp := range p.AsList() {
			subProp.setContext(ctx)
		}
	}
}

func (p *Property) setFileAndParentRange(target fs.FS, filepath string, parentRange iacTypes.Range) {
	p.rng = iacTypes.NewRange(filepath, p.rng.GetStartLine(), p.rng.GetEndLine(), p.rng.GetSourcePrefix(), target)
	p.parentRange = parentRange

	switch p.Type() {
	case cftypes.Map:
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(target, filepath, parentRange)
		}
	case cftypes.List:
		for _, subProp := range p.AsList() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(target, filepath, parentRange)
		}
	}
}

func (p *Property) UnmarshalYAML(node *yaml.Node) error {
	p.rng = iacTypes.NewRange("", node.Line, calculateEndLine(node), "", nil)

	p.comment = node.LineComment
	return setPropertyValueFromYaml(node, &p.Inner)
}

func (p *Property) UnmarshalJSONWithMetadata(node jfather.Node) error {
	p.rng = iacTypes.NewRange("", node.Range().Start.Line, node.Range().End.Line, "", nil)
	return setPropertyValueFromJson(node, &p.Inner)
}

func (p *Property) Type() cftypes.CfType {
	return p.Inner.Type
}

func (p *Property) Range() iacTypes.Range {
	return p.rng
}

func (p *Property) Metadata() iacTypes.Metadata {
	base := p
	if p.isFunction() {
		if resolved, ok := p.resolveValue(); ok {
			base = resolved
		}
	}
	ref := NewCFReferenceWithValue(p.parentRange, *base, p.logicalId)
	return iacTypes.NewMetadata(p.Range(), ref.String())
}

func (p *Property) MetadataWithValue(resolvedValue *Property) iacTypes.Metadata {
	ref := NewCFReferenceWithValue(p.parentRange, *resolvedValue, p.logicalId)
	return iacTypes.NewMetadata(p.Range(), ref.String())
}

func (p *Property) isFunction() bool {
	if p == nil {
		return false
	}
	if p.Type() == cftypes.Map {
		for n := range p.AsMap() {
			return IsIntrinsic(n)
		}
	}
	return false
}

func (p *Property) RawValue() interface{} {
	return p.Inner.Value
}

func (p *Property) AsRawStrings() ([]string, error) {

	if len(p.ctx.lines) < p.rng.GetEndLine() {
		return p.ctx.lines, nil
	}
	return p.ctx.lines[p.rng.GetStartLine()-1 : p.rng.GetEndLine()], nil
}

func (p *Property) resolveValue() (*Property, bool) {
	if !p.isFunction() || p.IsUnresolved() {
		return p, true
	}

	resolved, ok := ResolveIntrinsicFunc(p)
	if ok {
		return resolved, true
	}

	p.unresolved = true
	return p, false
}

func (p *Property) GetStringProperty(path string, defaultValue ...string) iacTypes.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return iacTypes.StringUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)
	if prop.IsNotString() {
		return p.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

func (p *Property) StringDefault(defaultValue string) iacTypes.StringValue {
	return iacTypes.StringDefault(defaultValue, p.Metadata())
}

func (p *Property) GetBoolProperty(path string, defaultValue ...bool) iacTypes.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return iacTypes.BoolUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)

	if prop.isFunction() {
		prop, _ = prop.resolveValue()
	}

	if prop.IsNotBool() {
		return p.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

func (p *Property) GetIntProperty(path string, defaultValue ...int) iacTypes.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return iacTypes.IntUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)

	if prop.IsNotInt() {
		return p.IntDefault(defVal)
	}
	return prop.AsIntValue()
}

func (p *Property) BoolDefault(defaultValue bool) iacTypes.BoolValue {
	return iacTypes.BoolDefault(defaultValue, p.Metadata())
}

func (p *Property) IntDefault(defaultValue int) iacTypes.IntValue {
	return iacTypes.IntDefault(defaultValue, p.Metadata())
}

func (p *Property) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := p

	if p.isFunction() {
		property, _ = p.resolveValue()
	}

	if property.IsNotMap() {
		return nil
	}

	for n, p := range property.AsMap() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 || property == nil {
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		if nestedProperty.isFunction() {
			resolved, _ := nestedProperty.resolveValue()
			return resolved
		} else {
			return nestedProperty
		}
	}

	return &Property{}
}

func (p *Property) deriveResolved(propType cftypes.CfType, propValue interface{}) *Property {
	return &Property{
		ctx:         p.ctx,
		name:        p.name,
		comment:     p.comment,
		rng:         p.rng,
		parentRange: p.parentRange,
		logicalId:   p.logicalId,
		Inner: PropertyInner{
			Type:  propType,
			Value: propValue,
		},
	}
}

func (p *Property) ParentRange() iacTypes.Range {
	return p.parentRange
}

func (p *Property) inferBool(prop *Property, defaultValue bool) iacTypes.BoolValue {
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

	return p.BoolDefault(defaultValue)
}

func (p *Property) String() string {
	r := ""
	switch p.Type() {
	case cftypes.String:
		r = p.AsString()
	case cftypes.Int:
		r = strconv.Itoa(p.AsInt())
	}
	return r
}

func (p *Property) SetLogicalResource(id string) {
	p.logicalId = id

	if p.isFunction() {
		return
	}

	if p.IsMap() {
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.SetLogicalResource(id)
		}
	}

	if p.IsList() {
		for _, subProp := range p.AsList() {
			subProp.SetLogicalResource(id)
		}
	}

}

func (p *Property) GetJsonBytes(squashList ...bool) []byte {
	if p.IsNil() {
		return []byte{}
	}
	lines, err := p.AsRawStrings()
	if err != nil {
		return nil
	}
	if p.ctx.SourceFormat == JsonSourceFormat {
		return []byte(strings.Join(lines, " "))
	}

	if len(squashList) > 0 {
		lines[0] = strings.Replace(lines[0], "-", " ", 1)
	}

	lines = removeLeftMargin(lines)

	yamlContent := strings.Join(lines, "\n")
	var body interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &body); err != nil {
		return nil
	}
	jsonBody := convert(body)
	policyJson, err := json.Marshal(jsonBody)
	if err != nil {
		return nil
	}
	return policyJson
}

func (p *Property) GetJsonBytesAsString(squashList ...bool) string {
	return string(p.GetJsonBytes(squashList...))
}

func removeLeftMargin(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	prefixSpace := len(lines[0]) - len(strings.TrimLeft(lines[0], " "))

	for i, line := range lines {
		if len(line) >= prefixSpace {
			lines[i] = line[prefixSpace:]
		}
	}
	return lines
}

func convert(input interface{}) interface{} {
	switch x := input.(type) {
	case map[interface{}]interface{}:
		outpMap := make(map[string]interface{})
		for k, v := range x {
			outpMap[k.(string)] = convert(v)
		}
		return outpMap
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return input
}
