package parser

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveJoin(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Join"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Join should have exactly 2 values, returning original Property")
	}

	joiner := refValue[0].AsString()
	items := refValue[1].AsList()

	var itemValues []string
	for _, item := range items {
		resolved, success := item.resolveValue()
		if success {
			itemValues = append(itemValues, resolved.AsString())
		}
	}

	joined := strings.Join(itemValues, joiner)

	return property.deriveResolved(cftypes.String, joined), true
}
