package parser

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveGetAtt(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValueProp := property.AsMap()["Fn::GetAtt"]

	var refValue []string

	if refValueProp.IsString() {
		refValue = strings.Split(refValueProp.AsString(), ".")
	}

	if refValueProp.IsList() {
		for _, p := range refValueProp.AsList() {
			refValue = append(refValue, p.AsString())
		}
	}

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::GetAtt should have exactly 2 values, returning original Property")
	}

	logicalId := refValue[0]
	attribute := refValue[1]

	referencedResource := property.ctx.GetResourceByLogicalID(logicalId)
	if referencedResource == nil || referencedResource.IsNil() {
		return property.deriveResolved(cftypes.String, ""), true
	}

	referencedProperty := referencedResource.GetProperty(attribute)
	if referencedProperty.IsNil() {
		return property.deriveResolved(cftypes.String, referencedResource.ID()), true
	}

	return property.deriveResolved(referencedProperty.Type(), referencedProperty.RawValue()), true
}
