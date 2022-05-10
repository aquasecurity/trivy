// Copyright 2015 xeipuuv ( https://github.com/xeipuuv )
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// author           xeipuuv
// author-github    https://github.com/xeipuuv
// author-mail      xeipuuv@gmail.com
//
// repository-name  gojsonschema
// repository-desc  An implementation of JSON Schema, based on IETF's draft v4 - Go language.
//
// description      Extends Schema and SubSchema, implements the validation phase.
//
// created          28-02-2013

package gojsonschema

import (
	"encoding/json"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Validate loads and validates a JSON schema
func Validate(ls JSONLoader, ld JSONLoader) (*Result, error) {
	// load schema
	schema, err := NewSchema(ls)
	if err != nil {
		return nil, err
	}
	return schema.Validate(ld)
}

// Validate loads and validates a JSON document
func (v *Schema) Validate(l JSONLoader) (*Result, error) {
	root, err := l.LoadJSON()
	if err != nil {
		return nil, err
	}
	return v.validateDocument(root), nil
}

func (v *Schema) validateDocument(root interface{}) *Result {
	result := &Result{}
	context := NewJSONContext(StringContextRoot, nil)
	v.RootSchema.validateRecursive(v.RootSchema, root, result, context)
	return result
}

func (v *SubSchema) subValidateWithContext(document interface{}, context *JSONContext) *Result {
	result := &Result{}
	v.validateRecursive(v, document, result, context)
	return result
}

// Walker function to validate the json recursively against the SubSchema
func (v *SubSchema) validateRecursive(currentSubSchema *SubSchema, currentNode interface{}, result *Result, context *JSONContext) {

	if internalLogEnabled {
		internalLog("validateRecursive %s", context.String())
		internalLog(" %v", currentNode)
	}

	// Handle true/false schema as early as possible as all other fields will be nil
	if currentSubSchema.pass != nil {
		if !*currentSubSchema.pass {
			result.addInternalError(
				new(FalseError),
				context,
				currentNode,
				ErrorDetails{},
			)
		}
		return
	}

	// Handle referenced schemas, returns directly when a $ref is found
	if currentSubSchema.RefSchema != nil {
		v.validateRecursive(currentSubSchema.RefSchema, currentNode, result, context)
		return
	}

	// Check for null value
	if currentNode == nil {
		if currentSubSchema.Types.IsTyped() && !currentSubSchema.Types.Contains(TypeNull) {
			result.addInternalError(
				new(InvalidTypeError),
				context,
				currentNode,
				ErrorDetails{
					"expected": currentSubSchema.Types.String(),
					"given":    TypeNull,
				},
			)
			return
		}

		currentSubSchema.validateSchema(currentSubSchema, currentNode, result, context)
		v.validateCommon(currentSubSchema, currentNode, result, context)

	} else { // Not a null value

		if value, isNumber := currentNode.(json.Number); isNumber {
			isInt := checkJSONInteger(value)

			validType := currentSubSchema.Types.Contains(TypeNumber) || (isInt && currentSubSchema.Types.Contains(TypeInteger))

			if currentSubSchema.Types.IsTyped() && !validType {

				givenType := TypeInteger
				if !isInt {
					givenType = TypeNumber
				}

				result.addInternalError(
					new(InvalidTypeError),
					context,
					currentNode,
					ErrorDetails{
						"expected": currentSubSchema.Types.String(),
						"given":    givenType,
					},
				)
				return
			}

			currentSubSchema.validateSchema(currentSubSchema, value, result, context)
			v.validateNumber(currentSubSchema, value, result, context)
			v.validateCommon(currentSubSchema, value, result, context)
			v.validateString(currentSubSchema, value, result, context)

		} else {

			rValue := reflect.ValueOf(currentNode)
			rKind := rValue.Kind()

			switch rKind {

			// Slice => JSON array

			case reflect.Slice:

				if currentSubSchema.Types.IsTyped() && !currentSubSchema.Types.Contains(TypeArray) {
					result.addInternalError(
						new(InvalidTypeError),
						context,
						currentNode,
						ErrorDetails{
							"expected": currentSubSchema.Types.String(),
							"given":    TypeArray,
						},
					)
					return
				}

				castCurrentNode := currentNode.([]interface{})

				currentSubSchema.validateSchema(currentSubSchema, castCurrentNode, result, context)

				v.validateArray(currentSubSchema, castCurrentNode, result, context)
				v.validateCommon(currentSubSchema, castCurrentNode, result, context)

			// Map => JSON object

			case reflect.Map:
				if currentSubSchema.Types.IsTyped() && !currentSubSchema.Types.Contains(TypeObject) {
					result.addInternalError(
						new(InvalidTypeError),
						context,
						currentNode,
						ErrorDetails{
							"expected": currentSubSchema.Types.String(),
							"given":    TypeObject,
						},
					)
					return
				}

				castCurrentNode, ok := currentNode.(map[string]interface{})
				if !ok {
					castCurrentNode = convertDocumentNode(currentNode).(map[string]interface{})
				}

				currentSubSchema.validateSchema(currentSubSchema, castCurrentNode, result, context)

				v.validateObject(currentSubSchema, castCurrentNode, result, context)
				v.validateCommon(currentSubSchema, castCurrentNode, result, context)

				for _, pSchema := range currentSubSchema.PropertiesChildren {
					nextNode, ok := castCurrentNode[pSchema.Property]
					if ok {
						subContext := NewJSONContext(pSchema.Property, context)
						v.validateRecursive(pSchema, nextNode, result, subContext)
					}
				}

			// Simple JSON values : string, number, boolean

			case reflect.Bool:

				if currentSubSchema.Types.IsTyped() && !currentSubSchema.Types.Contains(TypeBoolean) {
					result.addInternalError(
						new(InvalidTypeError),
						context,
						currentNode,
						ErrorDetails{
							"expected": currentSubSchema.Types.String(),
							"given":    TypeBoolean,
						},
					)
					return
				}

				value := currentNode.(bool)

				currentSubSchema.validateSchema(currentSubSchema, value, result, context)
				v.validateNumber(currentSubSchema, value, result, context)
				v.validateCommon(currentSubSchema, value, result, context)
				v.validateString(currentSubSchema, value, result, context)

			case reflect.String:

				if currentSubSchema.Types.IsTyped() && !currentSubSchema.Types.Contains(TypeString) {
					result.addInternalError(
						new(InvalidTypeError),
						context,
						currentNode,
						ErrorDetails{
							"expected": currentSubSchema.Types.String(),
							"given":    TypeString,
						},
					)
					return
				}

				value := currentNode.(string)

				currentSubSchema.validateSchema(currentSubSchema, value, result, context)
				v.validateNumber(currentSubSchema, value, result, context)
				v.validateCommon(currentSubSchema, value, result, context)
				v.validateString(currentSubSchema, value, result, context)

			}

		}

	}

	result.incrementScore()
}

// Different kinds of validation there, SubSchema / common / array / object / string...
func (v *SubSchema) validateSchema(currentSubSchema *SubSchema, currentNode interface{}, result *Result, context *JSONContext) {

	if internalLogEnabled {
		internalLog("validateSchema %s", context.String())
		internalLog(" %v", currentNode)
	}

	if len(currentSubSchema.AnyOf) > 0 {

		validatedAnyOf := false
		var bestValidationResult *Result

		for _, anyOfSchema := range currentSubSchema.AnyOf {
			if !validatedAnyOf {
				validationResult := anyOfSchema.subValidateWithContext(currentNode, context)
				validatedAnyOf = validationResult.Valid()

				if !validatedAnyOf && (bestValidationResult == nil || validationResult.score > bestValidationResult.score) {
					bestValidationResult = validationResult
				}
			}
		}
		if !validatedAnyOf {

			result.addInternalError(new(NumberAnyOfError), context, currentNode, ErrorDetails{})

			if bestValidationResult != nil {
				// add error messages of closest matching SubSchema as
				// that's probably the one the user was trying to match
				result.mergeErrors(bestValidationResult)
			}
		}
	}

	if len(currentSubSchema.oneOf) > 0 {

		nbValidated := 0
		var bestValidationResult *Result

		for _, oneOfSchema := range currentSubSchema.oneOf {
			validationResult := oneOfSchema.subValidateWithContext(currentNode, context)
			if validationResult.Valid() {
				nbValidated++
			} else if nbValidated == 0 && (bestValidationResult == nil || validationResult.score > bestValidationResult.score) {
				bestValidationResult = validationResult
			}
		}

		if nbValidated != 1 {

			result.addInternalError(new(NumberOneOfError), context, currentNode, ErrorDetails{})

			if nbValidated == 0 {
				// add error messages of closest matching SubSchema as
				// that's probably the one the user was trying to match
				result.mergeErrors(bestValidationResult)
			}
		}

	}

	if len(currentSubSchema.AllOf) > 0 {
		nbValidated := 0

		for _, allOfSchema := range currentSubSchema.AllOf {
			validationResult := allOfSchema.subValidateWithContext(currentNode, context)
			if validationResult.Valid() {
				nbValidated++
			}
			result.mergeErrors(validationResult)
		}

		if nbValidated != len(currentSubSchema.AllOf) {
			result.addInternalError(new(NumberAllOfError), context, currentNode, ErrorDetails{})
		}
	}

	if currentSubSchema.not != nil {
		validationResult := currentSubSchema.not.subValidateWithContext(currentNode, context)
		if validationResult.Valid() {
			result.addInternalError(new(NumberNotError), context, currentNode, ErrorDetails{})
		}
	}

	if currentSubSchema.dependencies != nil && len(currentSubSchema.dependencies) > 0 {
		if currentNodeMap, ok := currentNode.(map[string]interface{}); ok {
			for elementKey := range currentNodeMap {
				if dependency, ok := currentSubSchema.dependencies[elementKey]; ok {
					switch dependency := dependency.(type) {

					case []string:
						for _, dependOnKey := range dependency {
							if _, dependencyResolved := currentNode.(map[string]interface{})[dependOnKey]; !dependencyResolved {
								result.addInternalError(
									new(MissingDependencyError),
									context,
									currentNode,
									ErrorDetails{"dependency": dependOnKey},
								)
							}
						}

					case *SubSchema:
						dependency.validateRecursive(dependency, currentNode, result, context)
					}
				}
			}
		}
	}

	if currentSubSchema._if != nil {
		validationResultIf := currentSubSchema._if.subValidateWithContext(currentNode, context)
		if currentSubSchema._then != nil && validationResultIf.Valid() {
			validationResultThen := currentSubSchema._then.subValidateWithContext(currentNode, context)
			if !validationResultThen.Valid() {
				result.addInternalError(new(ConditionThenError), context, currentNode, ErrorDetails{})
				result.mergeErrors(validationResultThen)
			}
		}
		if currentSubSchema._else != nil && !validationResultIf.Valid() {
			validationResultElse := currentSubSchema._else.subValidateWithContext(currentNode, context)
			if !validationResultElse.Valid() {
				result.addInternalError(new(ConditionElseError), context, currentNode, ErrorDetails{})
				result.mergeErrors(validationResultElse)
			}
		}
	}

	result.incrementScore()
}

func (v *SubSchema) validateCommon(currentSubSchema *SubSchema, value interface{}, result *Result, context *JSONContext) {

	if internalLogEnabled {
		internalLog("validateCommon %s", context.String())
		internalLog(" %v", value)
	}

	// const:
	if currentSubSchema._const != nil {
		vString, err := marshalWithoutNumber(value)
		if err != nil {
			result.addInternalError(new(InternalError), context, value, ErrorDetails{"error": err})
		}
		if *vString != *currentSubSchema._const {
			result.addInternalError(new(ConstError),
				context,
				value,
				ErrorDetails{
					"allowed": *currentSubSchema._const,
				},
			)
		}
	}

	// enum:
	if len(currentSubSchema.enum) > 0 {
		vString, err := marshalWithoutNumber(value)
		if err != nil {
			result.addInternalError(new(InternalError), context, value, ErrorDetails{"error": err})
		}
		if !isStringInSlice(currentSubSchema.enum, *vString) {
			result.addInternalError(
				new(EnumError),
				context,
				value,
				ErrorDetails{
					"allowed": strings.Join(currentSubSchema.enum, ", "),
				},
			)
		}
	}

	// format:
	if currentSubSchema.format != "" {
		if !FormatCheckers.IsFormat(currentSubSchema.format, value) {
			result.addInternalError(
				new(DoesNotMatchFormatError),
				context,
				value,
				ErrorDetails{"format": currentSubSchema.format},
			)
		}
	}

	result.incrementScore()
}

func (v *SubSchema) validateArray(currentSubSchema *SubSchema, value []interface{}, result *Result, context *JSONContext) {

	if internalLogEnabled {
		internalLog("validateArray %s", context.String())
		internalLog(" %v", value)
	}

	nbValues := len(value)

	// TODO explain
	if currentSubSchema.ItemsChildrenIsSingleSchema {
		for i := range value {
			subContext := NewJSONContext(strconv.Itoa(i), context)
			validationResult := currentSubSchema.ItemsChildren[0].subValidateWithContext(value[i], subContext)
			result.mergeErrors(validationResult)
		}
	} else {
		if currentSubSchema.ItemsChildren != nil && len(currentSubSchema.ItemsChildren) > 0 {

			nbItems := len(currentSubSchema.ItemsChildren)

			// while we have both schemas and values, check them against each other
			for i := 0; i != nbItems && i != nbValues; i++ {
				subContext := NewJSONContext(strconv.Itoa(i), context)
				validationResult := currentSubSchema.ItemsChildren[i].subValidateWithContext(value[i], subContext)
				result.mergeErrors(validationResult)
			}

			if nbItems < nbValues {
				// we have less schemas than elements in the instance array,
				// but that might be ok if "additionalItems" is specified.

				switch currentSubSchema.additionalItems.(type) {
				case bool:
					if !currentSubSchema.additionalItems.(bool) {
						result.addInternalError(new(ArrayNoAdditionalItemsError), context, value, ErrorDetails{})
					}
				case *SubSchema:
					additionalItemSchema := currentSubSchema.additionalItems.(*SubSchema)
					for i := nbItems; i != nbValues; i++ {
						subContext := NewJSONContext(strconv.Itoa(i), context)
						validationResult := additionalItemSchema.subValidateWithContext(value[i], subContext)
						result.mergeErrors(validationResult)
					}
				}
			}
		}
	}

	// minItems & maxItems
	if currentSubSchema.minItems != nil {
		if nbValues < int(*currentSubSchema.minItems) {
			result.addInternalError(
				new(ArrayMinItemsError),
				context,
				value,
				ErrorDetails{"min": *currentSubSchema.minItems},
			)
		}
	}
	if currentSubSchema.maxItems != nil {
		if nbValues > int(*currentSubSchema.maxItems) {
			result.addInternalError(
				new(ArrayMaxItemsError),
				context,
				value,
				ErrorDetails{"max": *currentSubSchema.maxItems},
			)
		}
	}

	// uniqueItems:
	if currentSubSchema.uniqueItems {
		var stringifiedItems = make(map[string]int)
		for j, v := range value {
			vString, err := marshalWithoutNumber(v)
			if err != nil {
				result.addInternalError(new(InternalError), context, value, ErrorDetails{"err": err})
			}
			if i, ok := stringifiedItems[*vString]; ok {
				result.addInternalError(
					new(ItemsMustBeUniqueError),
					context,
					value,
					ErrorDetails{"type": TypeArray, "i": i, "j": j},
				)
			}
			stringifiedItems[*vString] = j
		}
	}

	// contains:

	if currentSubSchema.contains != nil {
		validatedOne := false
		var bestValidationResult *Result

		for i, v := range value {
			subContext := NewJSONContext(strconv.Itoa(i), context)

			validationResult := currentSubSchema.contains.subValidateWithContext(v, subContext)
			if validationResult.Valid() {
				validatedOne = true
				break
			} else {
				if bestValidationResult == nil || validationResult.score > bestValidationResult.score {
					bestValidationResult = validationResult
				}
			}
		}
		if !validatedOne {
			result.addInternalError(
				new(ArrayContainsError),
				context,
				value,
				ErrorDetails{},
			)
			if bestValidationResult != nil {
				result.mergeErrors(bestValidationResult)
			}
		}
	}

	result.incrementScore()
}

func (v *SubSchema) validateObject(currentSubSchema *SubSchema, value map[string]interface{}, result *Result, context *JSONContext) {

	if internalLogEnabled {
		internalLog("validateObject %s", context.String())
		internalLog(" %v", value)
	}

	// minProperties & maxProperties:
	if currentSubSchema.minProperties != nil {
		if len(value) < int(*currentSubSchema.minProperties) {
			result.addInternalError(
				new(ArrayMinPropertiesError),
				context,
				value,
				ErrorDetails{"min": *currentSubSchema.minProperties},
			)
		}
	}
	if currentSubSchema.maxProperties != nil {
		if len(value) > int(*currentSubSchema.maxProperties) {
			result.addInternalError(
				new(ArrayMaxPropertiesError),
				context,
				value,
				ErrorDetails{"max": *currentSubSchema.maxProperties},
			)
		}
	}

	// required:
	for _, requiredProperty := range currentSubSchema.required {
		_, ok := value[requiredProperty]
		if ok {
			result.incrementScore()
		} else {
			result.addInternalError(
				new(RequiredError),
				context,
				value,
				ErrorDetails{"property": requiredProperty},
			)
		}
	}

	// additionalProperty & patternProperty:
	for pk := range value {

		// Check whether this property is described by "properties"
		found := false
		for _, spValue := range currentSubSchema.PropertiesChildren {
			if pk == spValue.Property {
				found = true
			}
		}

		//  Check whether this property is described by "patternProperties"
		ppMatch := v.validatePatternProperty(currentSubSchema, pk, value[pk], result, context)

		// If it is not described by neither "properties" nor "patternProperties" it must pass "additionalProperties"
		if !found && !ppMatch {
			switch ap := currentSubSchema.additionalProperties.(type) {
			case bool:
				// Handle the boolean case separately as it's cleaner to return a specific error than failing to pass the false schema
				if !ap {
					result.addInternalError(
						new(AdditionalPropertyNotAllowedError),
						context,
						value[pk],
						ErrorDetails{"property": pk},
					)

				}
			case *SubSchema:
				validationResult := ap.subValidateWithContext(value[pk], NewJSONContext(pk, context))
				result.mergeErrors(validationResult)
			}
		}
	}

	// propertyNames:
	if currentSubSchema.propertyNames != nil {
		for pk := range value {
			validationResult := currentSubSchema.propertyNames.subValidateWithContext(pk, context)
			if !validationResult.Valid() {
				result.addInternalError(new(InvalidPropertyNameError),
					context,
					value, ErrorDetails{
						"property": pk,
					})
				result.mergeErrors(validationResult)
			}
		}
	}

	result.incrementScore()
}

func (v *SubSchema) validatePatternProperty(currentSubSchema *SubSchema, key string, value interface{}, result *Result, context *JSONContext) bool {

	if internalLogEnabled {
		internalLog("validatePatternProperty %s", context.String())
		internalLog(" %s %v", key, value)
	}

	validated := false

	for pk, pv := range currentSubSchema.patternProperties {
		if matches, _ := regexp.MatchString(pk, key); matches {
			validated = true
			subContext := NewJSONContext(key, context)
			validationResult := pv.subValidateWithContext(value, subContext)
			result.mergeErrors(validationResult)
		}
	}

	if !validated {
		return false
	}

	result.incrementScore()
	return true
}

func (v *SubSchema) validateString(currentSubSchema *SubSchema, value interface{}, result *Result, context *JSONContext) {

	// Ignore JSON numbers
	stringValue, isString := value.(string)
	if !isString {
		return
	}

	if internalLogEnabled {
		internalLog("validateString %s", context.String())
		internalLog(" %v", value)
	}

	// minLength & maxLength:
	if currentSubSchema.minLength != nil {
		if utf8.RuneCount([]byte(stringValue)) < int(*currentSubSchema.minLength) {
			result.addInternalError(
				new(StringLengthGTEError),
				context,
				value,
				ErrorDetails{"min": *currentSubSchema.minLength},
			)
		}
	}
	if currentSubSchema.maxLength != nil {
		if utf8.RuneCount([]byte(stringValue)) > int(*currentSubSchema.maxLength) {
			result.addInternalError(
				new(StringLengthLTEError),
				context,
				value,
				ErrorDetails{"max": *currentSubSchema.maxLength},
			)
		}
	}

	// pattern:
	if currentSubSchema.pattern != nil {
		if !currentSubSchema.pattern.MatchString(stringValue) {
			result.addInternalError(
				new(DoesNotMatchPatternError),
				context,
				value,
				ErrorDetails{"pattern": currentSubSchema.pattern},
			)

		}
	}

	result.incrementScore()
}

func (v *SubSchema) validateNumber(currentSubSchema *SubSchema, value interface{}, result *Result, context *JSONContext) {

	// Ignore non numbers
	number, isNumber := value.(json.Number)
	if !isNumber {
		return
	}

	if internalLogEnabled {
		internalLog("validateNumber %s", context.String())
		internalLog(" %v", value)
	}

	float64Value, _ := new(big.Rat).SetString(string(number))

	// multipleOf:
	if currentSubSchema.multipleOf != nil {
		if q := new(big.Rat).Quo(float64Value, currentSubSchema.multipleOf); !q.IsInt() {
			result.addInternalError(
				new(MultipleOfError),
				context,
				number,
				ErrorDetails{
					"multiple": new(big.Float).SetRat(currentSubSchema.multipleOf),
				},
			)
		}
	}

	//maximum & exclusiveMaximum:
	if currentSubSchema.maximum != nil {
		if float64Value.Cmp(currentSubSchema.maximum) == 1 {
			result.addInternalError(
				new(NumberLTEError),
				context,
				number,
				ErrorDetails{
					"max": new(big.Float).SetRat(currentSubSchema.maximum),
				},
			)
		}
	}
	if currentSubSchema.exclusiveMaximum != nil {
		if float64Value.Cmp(currentSubSchema.exclusiveMaximum) >= 0 {
			result.addInternalError(
				new(NumberLTError),
				context,
				number,
				ErrorDetails{
					"max": new(big.Float).SetRat(currentSubSchema.exclusiveMaximum),
				},
			)
		}
	}

	//minimum & exclusiveMinimum:
	if currentSubSchema.minimum != nil {
		if float64Value.Cmp(currentSubSchema.minimum) == -1 {
			result.addInternalError(
				new(NumberGTEError),
				context,
				number,
				ErrorDetails{
					"min": new(big.Float).SetRat(currentSubSchema.minimum),
				},
			)
		}
	}
	if currentSubSchema.exclusiveMinimum != nil {
		if float64Value.Cmp(currentSubSchema.exclusiveMinimum) <= 0 {
			result.addInternalError(
				new(NumberGTError),
				context,
				number,
				ErrorDetails{
					"min": new(big.Float).SetRat(currentSubSchema.exclusiveMinimum),
				},
			)
		}
	}

	result.incrementScore()
}
