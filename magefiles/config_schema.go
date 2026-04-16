//go:build mage_docs

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/aquasecurity/trivy/pkg/flag"
)

// JSON Schema type constants
const (
	schemaTypeString  = "string"
	schemaTypeBoolean = "boolean"
	schemaTypeInteger = "integer"
	schemaTypeNumber  = "number"
	schemaTypeArray   = "array"
	schemaTypeObject  = "object"
)

const configSchemaPath = "schema/trivy-config.json"

// generateConfigSchema generates a JSON schema for trivy.yaml configuration file.
func generateConfigSchema(outputPath string, allFlagGroups []flag.FlagGroup) error {
	root := &jsonschema.Schema{
		Schema:      "https://json-schema.org/draft/2020-12/schema",
		Type:        schemaTypeObject,
		Title:       "Trivy Configuration",
		Description: "Configuration file for Trivy security scanner (trivy.yaml)",
		Properties:  make(map[string]*jsonschema.Schema),
	}

	for _, group := range allFlagGroups {
		for _, f := range group.Flags() {
			configName := f.GetConfigName()
			if configName == "" || f.Hidden() {
				continue
			}
			if err := addFlagToSchema(root, f); err != nil {
				return err
			}
		}
	}

	data, err := marshalOrdered(root, []string{"$schema", "type", "title", "description"})
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll("schema", 0755); err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// marshalOrdered marshals v to indented JSON with the given keys appearing
// first in the output. Remaining keys follow in sorted order.
// This is needed because the jsonschema library fixes the field order
// in its MarshalJSON implementation.
func marshalOrdered(v any, firstKeys []string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}

	written := make(map[string]bool, len(firstKeys))
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true

	writeField := func(k string, v json.RawMessage) {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		key, _ := json.Marshal(k)
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(v)
	}

	for _, k := range firstKeys {
		v, ok := fields[k]
		if !ok {
			continue
		}
		writeField(k, v)
		written[k] = true
	}

	remaining := make([]string, 0, len(fields))
	for k := range fields {
		if !written[k] {
			remaining = append(remaining, k)
		}
	}
	sort.Strings(remaining)
	for _, k := range remaining {
		writeField(k, fields[k])
	}

	buf.WriteByte('}')

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	return pretty.Bytes(), nil
}

// addFlagToSchema adds a flag to the schema, creating nested objects as needed.
func addFlagToSchema(root *jsonschema.Schema, f flag.Flagger) error {
	configName := f.GetConfigName()
	parts := strings.Split(configName, ".")

	// Split into parent path and leaf name
	parentParts, leafName := parts[:len(parts)-1], parts[len(parts)-1]

	// Navigate/create intermediate objects
	current := root
	for _, part := range parentParts {
		if existing, ok := current.Properties[part]; ok {
			current = existing
		} else {
			newSchema := &jsonschema.Schema{
				Type:       schemaTypeObject,
				Properties: make(map[string]*jsonschema.Schema),
			}
			current.Properties[part] = newSchema
			current.PropertyOrder = append(current.PropertyOrder, part)
			current = newSchema
		}
	}

	// Add the leaf property
	schema, err := schemaFromFlag(f)
	if err != nil {
		return err
	}
	current.Properties[leafName] = schema
	current.PropertyOrder = append(current.PropertyOrder, leafName)
	return nil
}

// schemaFromFlag creates a JSON schema based on the flag's type, description, and allowed values.
func schemaFromFlag(f flag.Flagger) (*jsonschema.Schema, error) {
	schema, err := schemaFromFlagValue(f.GetDefaultValue())
	if err != nil {
		return nil, fmt.Errorf("flag %q: %w", f.GetConfigName(), err)
	}

	// Add description from Usage
	if usage := f.GetUsage(); usage != "" {
		schema.Description = usage
	}

	// Add enum if Values is set
	if values := f.GetValues(); len(values) > 0 {
		enumValues := make([]any, len(values))
		for i, v := range values {
			enumValues[i] = v
		}
		// For array types, enum should be in items, not at the array level
		if schema.Type == schemaTypeArray && schema.Items != nil {
			schema.Items.Enum = enumValues
		} else {
			schema.Enum = enumValues
		}
	}

	return schema, nil
}

// schemaFromFlagValue creates a JSON schema based on the flag's default value type.
func schemaFromFlagValue(val any) (*jsonschema.Schema, error) {
	switch val.(type) {
	case string:
		return &jsonschema.Schema{Type: schemaTypeString}, nil
	case bool:
		return &jsonschema.Schema{Type: schemaTypeBoolean}, nil
	case int:
		return &jsonschema.Schema{Type: schemaTypeInteger}, nil
	case float64:
		return &jsonschema.Schema{Type: schemaTypeNumber}, nil
	case []string:
		return &jsonschema.Schema{
			Type:  schemaTypeArray,
			Items: &jsonschema.Schema{Type: schemaTypeString},
		}, nil
	case time.Duration:
		return &jsonschema.Schema{Type: schemaTypeString}, nil
	case map[string][]string:
		return &jsonschema.Schema{
			Type: schemaTypeObject,
			AdditionalProperties: &jsonschema.Schema{
				Type:  schemaTypeArray,
				Items: &jsonschema.Schema{Type: schemaTypeString},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown type %T, please update schemaFromFlagValue()", val)
	}
}
