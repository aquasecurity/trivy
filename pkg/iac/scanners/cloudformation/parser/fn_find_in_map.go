package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveFindInMap(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::FindInMap"].AsList()

	if len(refValue) != 3 {
		return abortIntrinsic(property, "Fn::FindInMap should have exactly 3 values, returning original Property")
	}

	mapName := refValue[0].AsString()
	topLevelKey := refValue[1].AsString()
	secondaryLevelKey := refValue[2].AsString()

	if property.ctx == nil {
		return abortIntrinsic(property, "the property does not have an attached context, returning original Property")
	}

	m, ok := property.ctx.Mappings[mapName]
	if !ok {
		return abortIntrinsic(property, "could not find map %s, returning original Property")
	}

	mapContents := m.(map[string]interface{})

	k, ok := mapContents[topLevelKey]
	if !ok {
		return abortIntrinsic(property, "could not find %s in the %s map, returning original Property", topLevelKey, mapName)
	}

	mapValues := k.(map[string]interface{})

	if prop, ok := mapValues[secondaryLevelKey]; !ok {
		return abortIntrinsic(property, "could not find a value for %s in %s, returning original Property", secondaryLevelKey, topLevelKey)
	} else {
		return property.deriveResolved(cftypes.String, prop), true
	}
}
