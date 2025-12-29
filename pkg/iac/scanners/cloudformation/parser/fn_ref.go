package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveReference(property *Property) (*Property, bool) {
	if !property.isFunction() {
		return property, true
	}

	refProp := property.AsMap()["Ref"]
	if refProp.IsNotString() {
		return property, false
	}
	refValue := refProp.AsString()

	if pseudo, ok := pseudoParameters[refValue]; ok {
		return property.deriveResolved(pseudo.t, pseudo.val), true
	}

	if property.loopCtx != nil {
		v, found := property.loopCtx.Resolve(refValue)
		if found {
			return property.deriveResolved(v.Type, v.RawValue()), true
		}
	}

	if property.ctx == nil {
		return property, false
	}

	if param, exists := property.ctx.Parameters[refValue]; exists {
		resolvedType := param.Type()

		switch param.Default().(type) {
		case bool:
			resolvedType = cftypes.Bool
		case string:
			resolvedType = cftypes.String
		case int:
			resolvedType = cftypes.Int
		}

		resolved := property.deriveResolved(resolvedType, param.Default())
		return resolved, true
	}

	if res, exists := property.ctx.Resources[refValue]; exists {
		resolved := property.deriveResolved(cftypes.String, res.ID())
		return resolved, true
	}

	return nil, false
}
