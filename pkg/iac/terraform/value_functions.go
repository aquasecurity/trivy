package terraform

import (
	"fmt"
	"regexp"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

const (
	functionNameKey = "action"
	valueNameKey    = "value"
)

var functions = map[string]func(interface{}, interface{}) bool{
	"isAny":        isAny,
	"isNone":       isNone,
	"regexMatches": regexMatches,
}

func evaluate(criteriaValue, testValue interface{}) bool {
	switch t := criteriaValue.(type) {
	case map[interface{}]interface{}:
		if t[functionNameKey] != nil {
			return executeFunction(t[functionNameKey].(string), t[valueNameKey], testValue)
		}
	case map[string]interface{}:
		if t[functionNameKey] != nil {
			return executeFunction(t[functionNameKey].(string), t[valueNameKey], testValue)
		}
	default:
		return t == testValue
	}
	return false
}

func executeFunction(functionName string, criteriaValues, testValue interface{}) bool {
	if functions[functionName] != nil {
		return functions[functionName](criteriaValues, testValue)
	}
	return false
}

func isAny(criteriaValues, testValue interface{}) bool {
	switch t := criteriaValues.(type) {
	case []interface{}:
		for _, v := range t {
			if v == testValue {
				return true
			}
		}
	case []string:
		for _, v := range t {
			if v == testValue.(string) {
				return true
			}
		}
	}
	return false
}

func isNone(criteriaValues, testValue interface{}) bool {
	return !isAny(criteriaValues, testValue)
}

func regexMatches(criteriaValue, testValue interface{}) bool {
	var patternVal string
	switch t := criteriaValue.(type) {
	case string:
		patternVal = fmt.Sprintf("%v", criteriaValue)
	case cty.Value:
		if err := gocty.FromCtyValue(t, &patternVal); err != nil {
			return false
		}
	default:
		return false
	}

	re, err := regexp.Compile(patternVal)
	if err != nil {
		return false
	}

	match := re.MatchString(fmt.Sprintf("%v", testValue))
	return match
}
