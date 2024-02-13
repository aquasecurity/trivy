package schemas

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/rego/convert"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

type RawSchema struct {
	Type       string               `json:"type"` // object
	Properties map[string]Property  `json:"properties,omitempty"`
	Defs       map[string]*Property `json:"definitions,omitempty"`
}

type Property struct {
	Type       string              `json:"type,omitempty"`
	Ref        string              `json:"$ref,omitempty"`
	Properties map[string]Property `json:"properties,omitempty"`
	Items      *Property           `json:"items,omitempty"`
}

type builder struct {
	schema RawSchema
}

func Build() (*RawSchema, error) {

	b := newBuilder()

	inputValue := reflect.ValueOf(state.State{})

	err := b.fromInput(inputValue)
	if err != nil {
		return nil, err
	}

	return &b.schema, nil
}

func newBuilder() *builder {
	return &builder{
		schema: RawSchema{
			Properties: nil,
			Defs:       nil,
		},
	}
}

func (b *builder) fromInput(inputValue reflect.Value) error {

	prop, err := b.readProperty("", nil, inputValue.Type(), 0)
	if err != nil {
		return err
	}
	if prop == nil {
		return fmt.Errorf("property is nil")
	}
	b.schema.Properties = prop.Properties
	b.schema.Type = prop.Type
	return nil
}

func refName(name string, parent, t reflect.Type) string {
	if t.Name() == "" { // inline struct
		return sanitize(parent.PkgPath() + "." + parent.Name() + "." + name)
	}
	return sanitize(t.PkgPath() + "." + t.Name())
}

func sanitize(s string) string {
	return strings.ReplaceAll(s, "/", ".")
}

func (b *builder) readProperty(name string, parent, inputType reflect.Type, indent int) (*Property, error) {

	if inputType.Kind() == reflect.Ptr {
		inputType = inputType.Elem()
	}

	switch inputType.String() {
	case "types.Metadata", "types.Range", "types.Reference":
		return nil, nil
	}

	if b.schema.Defs != nil {
		_, ok := b.schema.Defs[refName(name, parent, inputType)]
		if ok {
			return &Property{
				Type: "object",
				Ref:  "#/definitions/" + refName(name, parent, inputType),
			}, nil
		}
	}

	fmt.Println(strings.Repeat("  ", indent) + name)

	switch kind := inputType.Kind(); kind {
	case reflect.Struct:
		return b.readStruct(name, parent, inputType, indent)
	case reflect.Slice:
		return b.readSlice(name, parent, inputType, indent)
	case reflect.String:
		return &Property{
			Type: "string",
		}, nil
	case reflect.Int:
		return &Property{
			Type: "integer",
		}, nil
	case reflect.Bool:
		return &Property{
			Type: "boolean",
		}, nil
	case reflect.Float32, reflect.Float64:
		return &Property{
			Type: "number",
		}, nil
	}

	switch inputType.Name() {
	case "BoolValue":
		return &Property{
			Type: "object",
			Properties: map[string]Property{
				"value": {
					Type: "boolean",
				},
			},
		}, nil
	case "IntValue":
		return &Property{
			Type: "object",
			Properties: map[string]Property{
				"value": {
					Type: "integer",
				},
			},
		}, nil
	case "StringValue", "TimeValue", "BytesValue":
		return &Property{
			Type: "object",
			Properties: map[string]Property{
				"value": {
					Type: "string",
				},
			},
		}, nil
	case "MapValue":
		return &Property{
			Type: "object",
			Properties: map[string]Property{
				"value": {
					Type: "object",
				},
			},
		}, nil

	}

	fmt.Printf("WARNING: unsupported type: %s (%s)\n", inputType.Name(), inputType)
	return nil, nil
}

var converterInterface = reflect.TypeOf((*convert.Converter)(nil)).Elem()

func (b *builder) readStruct(name string, parent, inputType reflect.Type, indent int) (*Property, error) {

	if b.schema.Defs == nil {
		b.schema.Defs = make(map[string]*Property)
	}

	def := &Property{
		Type:       "object",
		Properties: make(map[string]Property),
	}

	if parent != nil {
		b.schema.Defs[refName(name, parent, inputType)] = def
	}

	if inputType.Implements(converterInterface) {
		if inputType.Kind() == reflect.Ptr {
			inputType = inputType.Elem()
		}
		returns := reflect.New(inputType).MethodByName("ToRego").Call(nil)
		if err := b.readRego(def, name, parent, returns[0].Type(), returns[0].Interface(), indent); err != nil {
			return nil, err
		}
	} else {

		for i := 0; i < inputType.NumField(); i++ {
			field := inputType.Field(i)
			prop, err := b.readProperty(field.Name, inputType, field.Type, indent+1)
			if err != nil {
				return nil, err
			}
			if prop == nil {
				continue
			}
			key := strings.ToLower(field.Name)
			if key == "metadata" {
				continue
			}
			def.Properties[key] = *prop
		}
	}

	if parent == nil {
		return def, nil
	}

	return &Property{
		Type: "object",
		Ref:  "#/definitions/" + refName(name, parent, inputType),
	}, nil
}

func (b *builder) readSlice(name string, parent, inputType reflect.Type, indent int) (*Property, error) {

	items, err := b.readProperty(name, parent, inputType.Elem(), indent+1)
	if err != nil {
		return nil, err
	}

	prop := &Property{
		Type:  "array",
		Items: items,
	}
	return prop, nil
}

func (b *builder) readRego(def *Property, name string, parent, typ reflect.Type, raw interface{}, indent int) error {

	switch cast := raw.(type) {
	case map[string]interface{}:
		def.Type = "object"
		for k, v := range cast {
			child := &Property{
				Properties: make(map[string]Property),
			}
			if err := b.readRego(child, k, reflect.TypeOf(raw), reflect.TypeOf(v), v, indent+1); err != nil {
				return err
			}
			def.Properties[k] = *child
		}
	case map[string]string:
		def.Type = "object"
		for k, v := range cast {
			child := &Property{
				Properties: make(map[string]Property),
			}
			if err := b.readRego(child, k, reflect.TypeOf(raw), reflect.TypeOf(v), v, indent+1); err != nil {
				return err
			}
			def.Properties[k] = *child
		}
	default:
		prop, err := b.readProperty(name, parent, typ, indent)
		if err != nil {
			return err
		}
		*def = *prop
	}

	return nil

}
