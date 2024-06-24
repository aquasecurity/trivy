package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveOr(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Or"].AsList()

	if len(refValue) < 2 {
		return abortIntrinsic(property, "Fn::Or should have at least 2 values, returning original Property")
	}

	results := make([]bool, len(refValue))
	for i := 0; i < len(refValue); i++ {

		r := false
		if refValue[i].IsBool() {
			r = refValue[i].AsBool()
		}

		results[i] = r
	}

	atleastOne := atleastOne(results)
	return property.deriveResolved(cftypes.Bool, atleastOne), true
}

func atleastOne(a []bool) bool {
	for _, b := range a {
		if b {
			return true
		}
	}

	return false
}
