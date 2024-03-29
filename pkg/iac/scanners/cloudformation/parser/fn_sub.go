package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveSub(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Sub"]

	if refValue.IsString() {
		return resolveStringSub(refValue, property), true
	}

	if refValue.IsList() {
		return resolveMapSub(refValue, property)
	}

	return property, false
}

func resolveMapSub(refValue, original *Property) (*Property, bool) {
	refValues := refValue.AsList()
	if len(refValues) != 2 {
		return abortIntrinsic(original, "Fn::Sub with list expects 2 values, returning original property")
	}

	workingString := refValues[0].AsString()
	components := refValues[1].AsMap()

	for k, v := range components {
		replacement := "[failed to resolve]"
		switch v.Type() {
		case cftypes.Map:
			resolved, _ := ResolveIntrinsicFunc(v)
			replacement = resolved.AsString()
		case cftypes.String:
			replacement = v.AsString()
		case cftypes.Int:
			replacement = strconv.Itoa(v.AsInt())
		case cftypes.Bool:
			replacement = fmt.Sprintf("%v", v.AsBool())
		case cftypes.List:
			var parts []string
			for _, p := range v.AsList() {
				parts = append(parts, p.String())
			}
			replacement = fmt.Sprintf("[%s]", strings.Join(parts, ", "))
		}
		workingString = strings.ReplaceAll(workingString, fmt.Sprintf("${%s}", k), replacement)
	}

	return original.deriveResolved(cftypes.String, workingString), true
}

func resolveStringSub(refValue, original *Property) *Property {
	workingString := refValue.AsString()

	for k, param := range pseudoParameters {
		workingString = strings.ReplaceAll(workingString, fmt.Sprintf("${%s}", k), fmt.Sprintf("%v", param.getRawValue()))
	}

	return original.deriveResolved(cftypes.String, workingString)
}
