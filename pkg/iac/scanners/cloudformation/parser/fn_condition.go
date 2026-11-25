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

	cond, exists := property.ctx.Conditions[refValue]
	if !exists {
		return nil, false
	}

	return property.ctx.resolveCondition(refValue, cond)
}
