package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveAnd(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::And"].AsList()

	if len(refValue) < 2 {
		return abortIntrinsic(property, "Fn::And should have at least 2 values, returning original Property")
	}

	results := make([]bool, len(refValue))
	for i := range refValue {

		r := false
		if refValue[i].IsBool() {
			r = refValue[i].AsBool()
		}

		results[i] = r
	}

	return property.deriveResolved(cftypes.Bool, allTrue(results)), true
}

func allTrue(a []bool) bool {
	for _, b := range a {
		if !b {
			return false
		}
	}

	return true
}
