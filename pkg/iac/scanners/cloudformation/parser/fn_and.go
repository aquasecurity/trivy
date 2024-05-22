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
	for i := 0; i < len(refValue); i++ {

		r := false
		if refValue[i].IsBool() {
			r = refValue[i].AsBool()
		}

		results[i] = r
	}

	theSame := allSameStrings(results)
	return property.deriveResolved(cftypes.Bool, theSame), true
}

func allSameStrings(a []bool) bool {
	for i := 1; i < len(a); i++ {
		if a[i] != a[0] {
			return false
		}
	}
	return true
}
