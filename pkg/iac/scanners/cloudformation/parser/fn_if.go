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

		name := condition.AsString()
		if cond := property.ctx.Conditions[name]; cond.isFunction() {
			con, ok := property.ctx.resolveCondition(name, cond)
			if ok && con.IsBool() {
				conditionMet = con.AsBool()
			}
		}
	}

	if conditionMet {
		return trueState, true
	}
	return falseState, true
}
