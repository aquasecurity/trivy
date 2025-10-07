package parser

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveFindInMap(property *Property) (*Property, bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::FindInMap"].AsList()

	if len(refValue) < 3 || len(refValue) > 4 {
		return abortIntrinsic(property, "Fn::FindInMap expects 3 or 4 arguments")
	}

	if property.ctx == nil {
		return abortIntrinsic(property, "property context is missing")
	}

	var defaultValue any
	if len(refValue) == 4 {
		if m := refValue[3].AsMap(); m != nil {
			if defProp, exists := m["DefaultValue"]; exists && defProp != nil {
				defaultValue = defProp.RawValue()
			}
		}
	}

	mapName := refValue[0].AsString()
	topKey := refValue[1].AsString()
	secKey := refValue[2].AsString()

	value, err := resolveMapping(property.ctx, mapName, topKey, secKey)
	if err != nil {
		if defaultValue == nil {
			return abortIntrinsic(property, err.Error())
		}
		value = defaultValue
	}

	switch v := value.(type) {
	case string:
		return property.deriveResolved(cftypes.String, v), true
	case []any:
		elems := make([]*Property, len(v))
		for i, el := range v {
			elems[i] = property.deriveResolved(cftypes.String, el)
		}
		return property.deriveResolved(cftypes.List, elems), true
	default:
		return abortIntrinsic(property, fmt.Sprintf("unsupported type in mapping: %T", v))
	}
}

func resolveMapping(ctx *FileContext, mapName, topKey, secKey string) (any, error) {
	m, ok := ctx.Mappings[mapName]
	if !ok {
		return nil, fmt.Errorf("map %s not found", mapName)
	}
	mapContents, ok := m.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("map %s has invalid type", mapName)
	}

	k, ok := mapContents[topKey]
	if !ok {
		return nil, fmt.Errorf("key %s not found in map %s", topKey, mapName)
	}
	mapValues := k.(map[string]any)

	prop, ok := mapValues[secKey]
	if !ok {
		return nil, fmt.Errorf("key %s not found in %s", secKey, topKey)
	}
	return prop, nil
}
