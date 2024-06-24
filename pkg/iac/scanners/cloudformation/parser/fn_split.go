package parser

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveSplit(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Split"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Split should have exactly 2 values, returning original Property")
	}

	delimiterProp := refValue[0]
	splitProp := refValue[1]

	if !splitProp.IsString() || !delimiterProp.IsString() {
		abortIntrinsic(property, "Fn::Split requires two strings as input, returning original Property")

	}

	propertyList := createPropertyList(splitProp, delimiterProp, property)

	return property.deriveResolved(cftypes.List, propertyList), true
}

func createPropertyList(splitProp, delimiterProp, parent *Property) []*Property {

	splitString := splitProp.AsString()
	delimiter := delimiterProp.AsString()

	splits := strings.Split(splitString, delimiter)
	var props []*Property
	for _, split := range splits {
		props = append(props, parent.deriveResolved(cftypes.String, split))
	}
	return props
}
