package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveNot(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Not"].AsList()

	if len(refValue) != 1 {
		return abortIntrinsic(property, "Fn::No should have at only 1 values, returning original Property")
	}

	funcToInvert, _ := refValue[0].resolveValue()

	if funcToInvert.IsBool() {
		return property.deriveResolved(cftypes.Bool, !funcToInvert.AsBool()), true
	}

	return property, false
}
