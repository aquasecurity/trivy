package parser

func ResolveIf(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::If"].AsList()

	if len(refValue) != 3 {
		return abortIntrinsic(property, "Fn::If should have exactly 3 values, returning original Property")
	}

	condition, _ := refValue[0].resolveValue()
	trueState, _ := refValue[1].resolveValue()
	falseState, _ := refValue[2].resolveValue()

	conditionMet := false

	con, _ := condition.resolveValue()
	if con.IsBool() {
		conditionMet = con.AsBool()
	} else if property.ctx.Conditions != nil &&
		condition.IsString() {

		condition := property.ctx.Conditions[condition.AsString()]
		if condition.isFunction() {
			con, _ := condition.resolveValue()
			if con.IsBool() {
				conditionMet = con.AsBool()
			}
		}
	}

	if conditionMet {
		return trueState, true
	} else {
		return falseState, true
	}
}
