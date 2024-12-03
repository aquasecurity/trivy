package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveEquals(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Equals"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Equals should have exactly 2 values, returning original Property")
	}

	propA, _ := refValue[0].resolveValue()
	propB, _ := refValue[1].resolveValue()
	return property.deriveResolved(cftypes.Bool, propA.EqualTo(propB.RawValue())), true
}
