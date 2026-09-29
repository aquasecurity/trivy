package parser

func ResolveCondition(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refProp := property.AsMap()["Condition"]
	if refProp.IsNotString() {
		return nil, false
	}
	refValue := refProp.AsString()

	for k, prop := range property.ctx.Conditions {
		if k == refValue {
			return prop.resolveValue()
		}
	}

	return nil, false
}
