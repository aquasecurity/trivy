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
// description      Defines Schema, the main entry to every SubSchema.
//                  Contains the parsing logic and error checking.
//
// created          26-02-2013

package gojsonschema

import (
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"text/template"

	"github.com/xeipuuv/gojsonreference"
)

var (
	// Locale is the default locale to use
	// Library users can overwrite with their own implementation
	Locale locale = DefaultLocale{}

	// ErrorTemplateFuncs allows you to define custom template funcs for use in localization.
	ErrorTemplateFuncs template.FuncMap
)

// NewSchema instances a schema using the given JSONLoader
func NewSchema(l JSONLoader) (*Schema, error) {
	return NewSchemaLoader().Compile(l)
}

// Schema holds a schema
type Schema struct {
	DocumentReference gojsonreference.JsonReference
	RootSchema        *SubSchema
	Pool              *schemaPool
	ReferencePool     *schemaReferencePool
}

func (d *Schema) parse(document interface{}, draft Draft) error {
	d.RootSchema = &SubSchema{Property: StringRootSchemaProperty, Draft: &draft}
	return d.parseSchema(document, d.RootSchema)
}

// SetRootSchemaName sets the root-schema name
func (d *Schema) SetRootSchemaName(name string) {
	d.RootSchema.Property = name
}

// Parses a SubSchema
//
// Pretty long function ( sorry :) )... but pretty straight forward, repetitive and boring
// Not much magic involved here, most of the job is to validate the key names and their values,
// then the values are copied into SubSchema struct
//
func (d *Schema) parseSchema(documentNode interface{}, currentSchema *SubSchema) error {

	if currentSchema.Draft == nil {
		if currentSchema.Parent == nil {
			return errors.New("Draft not set")
		}
		currentSchema.Draft = currentSchema.Parent.Draft
	}

	// As of draft 6 "true" is equivalent to an empty schema "{}" and false equals "{"not":{}}"
	if *currentSchema.Draft >= Draft6 {
		if b, isBool := documentNode.(bool); isBool {
			currentSchema.pass = &b
			return nil
		}
	}

	m, isMap := documentNode.(map[string]interface{})
	if !isMap {
		return errors.New(formatErrorDescription(
			Locale.ParseError(),
			ErrorDetails{
				"expected": StringSchema,
			},
		))
	}

	if currentSchema.Parent == nil {
		currentSchema.Ref = &d.DocumentReference
		currentSchema.ID = &d.DocumentReference
	}

	if currentSchema.ID == nil && currentSchema.Parent != nil {
		currentSchema.ID = currentSchema.Parent.ID
	}

	// In draft 6 the id keyword was renamed to $id
	// Hybrid mode uses the old id by default
	var keyID string

	switch *currentSchema.Draft {
	case Draft4:
		keyID = KeyID
	case Hybrid:
		keyID = KeyIDNew
		if _, found := m[KeyID]; found {
			keyID = KeyID
		}
	default:
		keyID = KeyIDNew
	}

	if id, err := getString(m, keyID); err != nil {
		return err
	} else if id != nil {
		jsonReference, err := gojsonreference.NewJsonReference(*id)
		if err != nil {
			return err
		}
		if currentSchema == d.RootSchema {
			currentSchema.ID = &jsonReference
		} else {
			ref, err := currentSchema.Parent.ID.Inherits(jsonReference)
			if err != nil {
				return err
			}
			currentSchema.ID = ref
		}
	}

	// definitions
	if v, ok := m[KeyDefinitions]; ok {
		switch mt := v.(type) {
		case map[string]interface{}:
			for _, dv := range mt {
				switch dv.(type) {
				case bool, map[string]interface{}:
					newSchema := &SubSchema{Property: KeyDefinitions, Parent: currentSchema}
					err := d.parseSchema(dv, newSchema)
					if err != nil {
						return err
					}
				default:
					return invalidType(StringArrayOfSchemas, KeyDefinitions)
				}
			}
		default:
			return invalidType(StringArrayOfSchemas, KeyDefinitions)
		}
	}

	// title
	var err error
	currentSchema.title, err = getString(m, KeyTitle)
	if err != nil {
		return err
	}

	// description
	currentSchema.description, err = getString(m, KeyDescription)
	if err != nil {
		return err
	}

	// $ref
	if ref, err := getString(m, KeyRef); err != nil {
		return err
	} else if ref != nil {
		jsonReference, err := gojsonreference.NewJsonReference(*ref)
		if err != nil {
			return err
		}

		currentSchema.Ref = &jsonReference

		if sch, ok := d.ReferencePool.Get(currentSchema.Ref.String()); ok {
			currentSchema.RefSchema = sch
		} else {
			return d.parseReference(documentNode, currentSchema)
		}
	}

	// type
	if typ, found := m[KeyType]; found {
		switch t := typ.(type) {
		case string:
			err := currentSchema.Types.Add(t)
			if err != nil {
				return err
			}
		case []interface{}:
			for _, typeInArray := range t {
				s, isString := typeInArray.(string)
				if !isString {
					return invalidType(KeyType, TypeString+"/"+StringArrayOfStrings)
				}
				if err := currentSchema.Types.Add(s); err != nil {
					return err
				}
			}
		default:
			return invalidType(KeyType, TypeString+"/"+StringArrayOfStrings)
		}
	}

	// properties
	if properties, found := m[KeyProperties]; found {
		err := d.parseProperties(properties, currentSchema)
		if err != nil {
			return err
		}
	}

	// additionalProperties
	if additionalProperties, found := m[KeyAdditionalProperties]; found {
		switch v := additionalProperties.(type) {
		case bool:
			currentSchema.additionalProperties = v
		case map[string]interface{}:
			newSchema := &SubSchema{Property: KeyAdditionalProperties, Parent: currentSchema, Ref: currentSchema.Ref}
			currentSchema.additionalProperties = newSchema
			err := d.parseSchema(v, newSchema)
			if err != nil {
				return errors.New(err.Error())
			}
		default:
			return invalidType(TypeBoolean+"/"+StringSchema, KeyAdditionalProperties)
		}
	}

	// patternProperties
	if patternProperties, err := getMap(m, KeyPatternProperties); err != nil {
		return err
	} else if patternProperties != nil {
		if len(patternProperties) > 0 {
			currentSchema.patternProperties = make(map[string]*SubSchema)
			for k, v := range patternProperties {
				_, err := regexp.MatchString(k, "")
				if err != nil {
					return errors.New(formatErrorDescription(
						Locale.RegexPattern(),
						ErrorDetails{"pattern": k},
					))
				}
				newSchema := &SubSchema{Property: k, Parent: currentSchema, Ref: currentSchema.Ref}
				err = d.parseSchema(v, newSchema)
				if err != nil {
					return errors.New(err.Error())
				}
				currentSchema.patternProperties[k] = newSchema
			}
		}
	}

	// propertyNames
	if propertyNames, found := m[KeyPropertyNames]; found && *currentSchema.Draft >= Draft6 {
		switch propertyNames.(type) {
		case bool, map[string]interface{}:
			newSchema := &SubSchema{Property: KeyPropertyNames, Parent: currentSchema, Ref: currentSchema.Ref}
			currentSchema.propertyNames = newSchema
			err := d.parseSchema(propertyNames, newSchema)
			if err != nil {
				return err
			}
		default:
			return errors.New(formatErrorDescription(
				Locale.InvalidType(),
				ErrorDetails{
					"expected": StringSchema,
					"given":    KeyPatternProperties,
				},
			))
		}
	}

	// dependencies
	if dependencies, found := m[KeyDependencies]; found {
		err := d.parseDependencies(dependencies, currentSchema)
		if err != nil {
			return err
		}
	}

	// items
	if items, found := m[KeyItems]; found {
		switch i := items.(type) {
		case []interface{}:
			for _, itemElement := range i {
				switch itemElement.(type) {
				case map[string]interface{}, bool:
					newSchema := &SubSchema{Parent: currentSchema, Property: KeyItems}
					newSchema.Ref = currentSchema.Ref
					currentSchema.ItemsChildren = append(currentSchema.ItemsChildren, newSchema)
					err := d.parseSchema(itemElement, newSchema)
					if err != nil {
						return err
					}
				default:
					return invalidType(StringSchema+"/"+StringArrayOfSchemas, KeyItems)
				}
				currentSchema.ItemsChildrenIsSingleSchema = false
			}
		case map[string]interface{}, bool:
			newSchema := &SubSchema{Parent: currentSchema, Property: KeyItems}
			newSchema.Ref = currentSchema.Ref
			currentSchema.ItemsChildren = append(currentSchema.ItemsChildren, newSchema)
			err := d.parseSchema(items, newSchema)
			if err != nil {
				return err
			}
			currentSchema.ItemsChildrenIsSingleSchema = true
		default:
			return invalidType(StringSchema+"/"+StringArrayOfSchemas, KeyItems)
		}
	}

	// additionalItems
	if additionalItems, found := m[KeyAdditionalItems]; found {
		switch i := additionalItems.(type) {
		case bool:
			currentSchema.additionalItems = i
		case map[string]interface{}:
			newSchema := &SubSchema{Property: KeyAdditionalItems, Parent: currentSchema, Ref: currentSchema.Ref}
			currentSchema.additionalItems = newSchema
			err := d.parseSchema(additionalItems, newSchema)
			if err != nil {
				return errors.New(err.Error())
			}
		default:
			return invalidType(TypeBoolean+"/"+StringSchema, KeyAdditionalItems)
		}
	}

	// validation : number / integer
	if multipleOf, found := m[KeyMultipleOf]; found {
		multipleOfValue := mustBeNumber(multipleOf)
		if multipleOfValue == nil {
			return invalidType(StringNumber, KeyMultipleOf)
		}
		if multipleOfValue.Cmp(big.NewRat(0, 1)) <= 0 {
			return errors.New(formatErrorDescription(
				Locale.GreaterThanZero(),
				ErrorDetails{"number": KeyMultipleOf},
			))
		}
		currentSchema.multipleOf = multipleOfValue
	}

	if minimum, found := m[KeyMinimum]; found {
		minimumValue := mustBeNumber(minimum)
		if minimumValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfA(),
				ErrorDetails{"x": KeyMinimum, "y": StringNumber},
			))
		}
		currentSchema.minimum = minimumValue
	}

	if exclusiveMinimum, found := m[KeyExclusiveMinimum]; found {
		switch *currentSchema.Draft {
		case Draft4:
			boolExclusiveMinimum, isBool := exclusiveMinimum.(bool)
			if !isBool {
				return invalidType(TypeBoolean, KeyExclusiveMinimum)
			}
			if currentSchema.minimum == nil {
				return errors.New(formatErrorDescription(
					Locale.CannotBeUsedWithout(),
					ErrorDetails{"x": KeyExclusiveMinimum, "y": KeyMinimum},
				))
			}
			if boolExclusiveMinimum {
				currentSchema.exclusiveMinimum = currentSchema.minimum
				currentSchema.minimum = nil
			}
		case Hybrid:
			switch b := exclusiveMinimum.(type) {
			case bool:
				if currentSchema.minimum == nil {
					return errors.New(formatErrorDescription(
						Locale.CannotBeUsedWithout(),
						ErrorDetails{"x": KeyExclusiveMinimum, "y": KeyMinimum},
					))
				}
				if b {
					currentSchema.exclusiveMinimum = currentSchema.minimum
					currentSchema.minimum = nil
				}
			case json.Number:
				currentSchema.exclusiveMinimum = mustBeNumber(m[KeyExclusiveMinimum])
			default:
				return invalidType(TypeBoolean+"/"+TypeNumber, KeyExclusiveMinimum)
			}
		default:
			if isJSONNumber(exclusiveMinimum) {
				currentSchema.exclusiveMinimum = mustBeNumber(exclusiveMinimum)
			} else {
				return invalidType(TypeNumber, KeyExclusiveMinimum)
			}
		}
	}

	if maximum, found := m[KeyMaximum]; found {
		maximumValue := mustBeNumber(maximum)
		if maximumValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfA(),
				ErrorDetails{"x": KeyMaximum, "y": StringNumber},
			))
		}
		currentSchema.maximum = maximumValue
	}

	if exclusiveMaximum, found := m[KeyExclusiveMaximum]; found {
		switch *currentSchema.Draft {
		case Draft4:
			boolExclusiveMaximum, isBool := exclusiveMaximum.(bool)
			if !isBool {
				return invalidType(TypeBoolean, KeyExclusiveMaximum)
			}
			if currentSchema.maximum == nil {
				return errors.New(formatErrorDescription(
					Locale.CannotBeUsedWithout(),
					ErrorDetails{"x": KeyExclusiveMaximum, "y": KeyMaximum},
				))
			}
			if boolExclusiveMaximum {
				currentSchema.exclusiveMaximum = currentSchema.maximum
				currentSchema.maximum = nil
			}
		case Hybrid:
			switch b := exclusiveMaximum.(type) {
			case bool:
				if currentSchema.maximum == nil {
					return errors.New(formatErrorDescription(
						Locale.CannotBeUsedWithout(),
						ErrorDetails{"x": KeyExclusiveMaximum, "y": KeyMaximum},
					))
				}
				if b {
					currentSchema.exclusiveMaximum = currentSchema.maximum
					currentSchema.maximum = nil
				}
			case json.Number:
				currentSchema.exclusiveMaximum = mustBeNumber(exclusiveMaximum)
			default:
				return invalidType(TypeBoolean+"/"+TypeNumber, KeyExclusiveMaximum)
			}
		default:
			if isJSONNumber(exclusiveMaximum) {
				currentSchema.exclusiveMaximum = mustBeNumber(exclusiveMaximum)
			} else {
				return invalidType(TypeNumber, KeyExclusiveMaximum)
			}
		}
	}

	// validation : string

	if minLength, found := m[KeyMinLength]; found {
		minLengthIntegerValue := mustBeInteger(minLength)
		if minLengthIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMinLength, "y": TypeInteger},
			))
		}
		if *minLengthIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMinLength},
			))
		}
		currentSchema.minLength = minLengthIntegerValue
	}

	if maxLength, found := m[KeyMaxLength]; found {
		maxLengthIntegerValue := mustBeInteger(maxLength)
		if maxLengthIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMaxLength, "y": TypeInteger},
			))
		}
		if *maxLengthIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMaxLength},
			))
		}
		currentSchema.maxLength = maxLengthIntegerValue
	}

	if currentSchema.minLength != nil && currentSchema.maxLength != nil {
		if *currentSchema.minLength > *currentSchema.maxLength {
			return errors.New(formatErrorDescription(
				Locale.CannotBeGT(),
				ErrorDetails{"x": KeyMinLength, "y": KeyMaxLength},
			))
		}
	}

	// NOTE: Regex compilation step removed as we don't use "pattern" attribute for
	// type checking, and this would cause schemas to fail if they included patterns
	// that were valid ECMA regex dialect but not known to Go (i.e. the regexp.Compile
	// function), such as patterns with negative lookahead
	if _, err := getString(m, KeyPattern); err != nil {
		return err
	}

	if format, err := getString(m, KeyFormat); err != nil {
		return err
	} else if format != nil {
		currentSchema.format = *format
	}

	// validation : object

	if minProperties, found := m[KeyMinProperties]; found {
		minPropertiesIntegerValue := mustBeInteger(minProperties)
		if minPropertiesIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMinProperties, "y": TypeInteger},
			))
		}
		if *minPropertiesIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMinProperties},
			))
		}
		currentSchema.minProperties = minPropertiesIntegerValue
	}

	if maxProperties, found := m[KeyMaxProperties]; found {
		maxPropertiesIntegerValue := mustBeInteger(maxProperties)
		if maxPropertiesIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMaxProperties, "y": TypeInteger},
			))
		}
		if *maxPropertiesIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMaxProperties},
			))
		}
		currentSchema.maxProperties = maxPropertiesIntegerValue
	}

	if currentSchema.minProperties != nil && currentSchema.maxProperties != nil {
		if *currentSchema.minProperties > *currentSchema.maxProperties {
			return errors.New(formatErrorDescription(
				Locale.KeyCannotBeGreaterThan(),
				ErrorDetails{"key": KeyMinProperties, "y": KeyMaxProperties},
			))
		}
	}

	required, err := getSlice(m, KeyRequired)
	if err != nil {
		return err
	}
	for _, requiredValue := range required {
		s, isString := requiredValue.(string)
		if !isString {
			return invalidType(TypeString, KeyRequired)
		} else if isStringInSlice(currentSchema.required, s) {
			return errors.New(formatErrorDescription(
				Locale.KeyItemsMustBeUnique(),
				ErrorDetails{"key": KeyRequired},
			))
		}
		currentSchema.required = append(currentSchema.required, s)
	}

	// validation : array

	if minItems, found := m[KeyMinItems]; found {
		minItemsIntegerValue := mustBeInteger(minItems)
		if minItemsIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMinItems, "y": TypeInteger},
			))
		}
		if *minItemsIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMinItems},
			))
		}
		currentSchema.minItems = minItemsIntegerValue
	}

	if maxItems, found := m[KeyMaxItems]; found {
		maxItemsIntegerValue := mustBeInteger(maxItems)
		if maxItemsIntegerValue == nil {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyMaxItems, "y": TypeInteger},
			))
		}
		if *maxItemsIntegerValue < 0 {
			return errors.New(formatErrorDescription(
				Locale.MustBeGTEZero(),
				ErrorDetails{"key": KeyMaxItems},
			))
		}
		currentSchema.maxItems = maxItemsIntegerValue
	}

	if uniqueItems, found := m[KeyUniqueItems]; found {
		bUniqueItems, isBool := uniqueItems.(bool)
		if !isBool {
			return errors.New(formatErrorDescription(
				Locale.MustBeOfA(),
				ErrorDetails{"x": KeyUniqueItems, "y": TypeBoolean},
			))
		}
		currentSchema.uniqueItems = bUniqueItems
	}

	if contains, found := m[KeyContains]; found && *currentSchema.Draft >= Draft6 {
		newSchema := &SubSchema{Property: KeyContains, Parent: currentSchema, Ref: currentSchema.Ref}
		currentSchema.contains = newSchema
		err := d.parseSchema(contains, newSchema)
		if err != nil {
			return err
		}
	}

	// validation : all
	if vConst, found := m[KeyConst]; found && *currentSchema.Draft >= Draft6 {
		is, err := marshalWithoutNumber(vConst)
		if err != nil {
			return err
		}
		currentSchema._const = is
	}

	enum, err := getSlice(m, KeyEnum)
	if err != nil {
		return err
	}
	for _, v := range enum {
		is, err := marshalWithoutNumber(v)
		if err != nil {
			return err
		}
		if isStringInSlice(currentSchema.enum, *is) {
			return errors.New(formatErrorDescription(
				Locale.KeyItemsMustBeUnique(),
				ErrorDetails{"key": KeyEnum},
			))
		}
		currentSchema.enum = append(currentSchema.enum, *is)
	}

	// validation : SubSchema
	oneOf, err := getSlice(m, KeyOneOf)
	if err != nil {
		return err
	}
	for _, v := range oneOf {
		newSchema := &SubSchema{Property: KeyOneOf, Parent: currentSchema, Ref: currentSchema.Ref}
		currentSchema.oneOf = append(currentSchema.oneOf, newSchema)
		err := d.parseSchema(v, newSchema)
		if err != nil {
			return err
		}
	}

	anyOf, err := getSlice(m, KeyAnyOf)
	if err != nil {
		return err
	}
	for _, v := range anyOf {
		newSchema := &SubSchema{Property: KeyAnyOf, Parent: currentSchema, Ref: currentSchema.Ref}
		currentSchema.AnyOf = append(currentSchema.AnyOf, newSchema)
		err := d.parseSchema(v, newSchema)
		if err != nil {
			return err
		}
	}

	allOf, err := getSlice(m, KeyAllOf)
	if err != nil {
		return err
	}
	for _, v := range allOf {
		newSchema := &SubSchema{Property: KeyAllOf, Parent: currentSchema, Ref: currentSchema.Ref}
		currentSchema.AllOf = append(currentSchema.AllOf, newSchema)
		err := d.parseSchema(v, newSchema)
		if err != nil {
			return err
		}
	}

	if vNot, found := m[KeyNot]; found {
		switch vNot.(type) {
		case bool, map[string]interface{}:
			newSchema := &SubSchema{Property: KeyNot, Parent: currentSchema, Ref: currentSchema.Ref}
			currentSchema.not = newSchema
			err := d.parseSchema(vNot, newSchema)
			if err != nil {
				return err
			}
		default:
			return errors.New(formatErrorDescription(
				Locale.MustBeOfAn(),
				ErrorDetails{"x": KeyNot, "y": TypeObject},
			))
		}
	}

	if *currentSchema.Draft >= Draft7 {
		if vIf, found := m[KeyIf]; found {
			switch vIf.(type) {
			case bool, map[string]interface{}:
				newSchema := &SubSchema{Property: KeyIf, Parent: currentSchema, Ref: currentSchema.Ref}
				currentSchema._if = newSchema
				err := d.parseSchema(vIf, newSchema)
				if err != nil {
					return err
				}
			default:
				return errors.New(formatErrorDescription(
					Locale.MustBeOfAn(),
					ErrorDetails{"x": KeyIf, "y": TypeObject},
				))
			}
		}

		if then, found := m[KeyThen]; found {
			switch then.(type) {
			case bool, map[string]interface{}:
				newSchema := &SubSchema{Property: KeyThen, Parent: currentSchema, Ref: currentSchema.Ref}
				currentSchema._then = newSchema
				err := d.parseSchema(then, newSchema)
				if err != nil {
					return err
				}
			default:
				return errors.New(formatErrorDescription(
					Locale.MustBeOfAn(),
					ErrorDetails{"x": KeyThen, "y": TypeObject},
				))
			}
		}

		if vElse, found := m[KeyElse]; found {
			switch vElse.(type) {
			case bool, map[string]interface{}:
				newSchema := &SubSchema{Property: KeyElse, Parent: currentSchema, Ref: currentSchema.Ref}
				currentSchema._else = newSchema
				err := d.parseSchema(vElse, newSchema)
				if err != nil {
					return err
				}
			default:
				return errors.New(formatErrorDescription(
					Locale.MustBeOfAn(),
					ErrorDetails{"x": KeyElse, "y": TypeObject},
				))
			}
		}
	}

	return nil
}

func (d *Schema) parseReference(documentNode interface{}, currentSchema *SubSchema) error {
	var (
		refdDocumentNode interface{}
		dsp              *schemaPoolDocument
		err              error
	)

	newSchema := &SubSchema{Property: KeyRef, Parent: currentSchema, Ref: currentSchema.Ref}

	d.ReferencePool.Add(currentSchema.Ref.String(), newSchema)

	dsp, err = d.Pool.GetDocument(*currentSchema.Ref)
	if err != nil {
		return err
	}
	newSchema.ID = currentSchema.Ref

	refdDocumentNode = dsp.Document
	newSchema.Draft = dsp.Draft

	switch refdDocumentNode.(type) {
	case bool, map[string]interface{}:
	// expected
	default:
		return errors.New(formatErrorDescription(
			Locale.MustBeOfType(),
			ErrorDetails{"key": StringSchema, "type": TypeObject},
		))
	}

	err = d.parseSchema(refdDocumentNode, newSchema)
	if err != nil {
		return err
	}

	currentSchema.RefSchema = newSchema

	return nil

}

func (d *Schema) parseProperties(documentNode interface{}, currentSchema *SubSchema) error {
	m, isMap := documentNode.(map[string]interface{})
	if !isMap {
		return errors.New(formatErrorDescription(
			Locale.MustBeOfType(),
			ErrorDetails{"key": StringProperties, "type": TypeObject},
		))
	}

	for k := range m {
		schemaProperty := k
		newSchema := &SubSchema{Property: schemaProperty, Parent: currentSchema, Ref: currentSchema.Ref}
		currentSchema.PropertiesChildren = append(currentSchema.PropertiesChildren, newSchema)
		err := d.parseSchema(m[k], newSchema)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Schema) parseDependencies(documentNode interface{}, currentSchema *SubSchema) error {
	m, isMap := documentNode.(map[string]interface{})
	if !isMap {
		return errors.New(formatErrorDescription(
			Locale.MustBeOfType(),
			ErrorDetails{"key": KeyDependencies, "type": TypeObject},
		))
	}
	currentSchema.dependencies = make(map[string]interface{})

	for k := range m {
		switch values := m[k].(type) {
		case []interface{}:
			var valuesToRegister []string
			for _, value := range values {
				str, isString := value.(string)
				if !isString {
					return errors.New(formatErrorDescription(
						Locale.MustBeOfType(),
						ErrorDetails{
							"key":  StringDependency,
							"type": StringSchemaOrArrayOfStrings,
						},
					))
				}
				valuesToRegister = append(valuesToRegister, str)
				currentSchema.dependencies[k] = valuesToRegister
			}

		case bool, map[string]interface{}:
			depSchema := &SubSchema{Property: k, Parent: currentSchema, Ref: currentSchema.Ref}
			err := d.parseSchema(m[k], depSchema)
			if err != nil {
				return err
			}
			currentSchema.dependencies[k] = depSchema

		default:
			return errors.New(formatErrorDescription(
				Locale.MustBeOfType(),
				ErrorDetails{
					"key":  StringDependency,
					"type": StringSchemaOrArrayOfStrings,
				},
			))
		}

	}

	return nil
}

func invalidType(expected, given string) error {
	return errors.New(formatErrorDescription(
		Locale.InvalidType(),
		ErrorDetails{
			"expected": expected,
			"given":    given,
		},
	))
}

func getString(m map[string]interface{}, key string) (*string, error) {
	v, found := m[key]
	if !found {
		// not found
		return nil, nil
	}
	s, isString := v.(string)
	if !isString {
		// wrong type
		return nil, invalidType(TypeString, key)
	}
	return &s, nil
}

func getMap(m map[string]interface{}, key string) (map[string]interface{}, error) {
	v, found := m[key]
	if !found {
		// not found
		return nil, nil
	}
	s, isMap := v.(map[string]interface{})
	if !isMap {
		// wrong type
		return nil, invalidType(StringSchema, key)
	}
	return s, nil
}

func getSlice(m map[string]interface{}, key string) ([]interface{}, error) {
	v, found := m[key]
	if !found {
		return nil, nil
	}
	s, isArray := v.([]interface{})
	if !isArray {
		return nil, errors.New(formatErrorDescription(
			Locale.MustBeOfAn(),
			ErrorDetails{"x": key, "y": TypeArray},
		))
	}
	return s, nil
}
