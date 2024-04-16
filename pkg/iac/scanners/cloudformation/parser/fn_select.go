package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveSelect(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Select"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Select should have exactly 2 values, returning original Property")
	}

	index := refValue[0]
	list := refValue[1]

	if index.IsNotInt() {
		if index.IsConvertableTo(cftypes.Int) {
			//
			index = index.ConvertTo(cftypes.Int)
		} else {
			return abortIntrinsic(property, "index on property [%s] should be an int, returning original Property", property.name)
		}
	}

	if list.IsNotList() {
		return abortIntrinsic(property, "list on property [%s] should be a list, returning original Property", property.name)
	}

	listItems := list.AsList()

	if len(listItems) <= index.AsInt() {
		return nil, false
	}

	return listItems[index.AsInt()], true
}
