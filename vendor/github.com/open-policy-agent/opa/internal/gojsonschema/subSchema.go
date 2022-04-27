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
// description      Defines the structure of a sub-SubSchema.
//                  A sub-SubSchema can contain other sub-schemas.
//
// created          27-02-2013

package gojsonschema

import (
	"math/big"
	"regexp"

	"github.com/xeipuuv/gojsonreference"
)

// Constants
const (
	KeySchema               = "$schema"
	KeyID                   = "id"
	KeyIDNew                = "$id"
	KeyRef                  = "$ref"
	KeyTitle                = "title"
	KeyDescription          = "description"
	KeyType                 = "type"
	KeyItems                = "items"
	KeyAdditionalItems      = "additionalItems"
	KeyProperties           = "properties"
	KeyPatternProperties    = "patternProperties"
	KeyAdditionalProperties = "additionalProperties"
	KeyPropertyNames        = "propertyNames"
	KeyDefinitions          = "definitions"
	KeyMultipleOf           = "multipleOf"
	KeyMinimum              = "minimum"
	KeyMaximum              = "maximum"
	KeyExclusiveMinimum     = "exclusiveMinimum"
	KeyExclusiveMaximum     = "exclusiveMaximum"
	KeyMinLength            = "minLength"
	KeyMaxLength            = "maxLength"
	KeyPattern              = "pattern"
	KeyFormat               = "format"
	KeyMinProperties        = "minProperties"
	KeyMaxProperties        = "maxProperties"
	KeyDependencies         = "dependencies"
	KeyRequired             = "required"
	KeyMinItems             = "minItems"
	KeyMaxItems             = "maxItems"
	KeyUniqueItems          = "uniqueItems"
	KeyContains             = "contains"
	KeyConst                = "const"
	KeyEnum                 = "enum"
	KeyOneOf                = "oneOf"
	KeyAnyOf                = "anyOf"
	KeyAllOf                = "allOf"
	KeyNot                  = "not"
	KeyIf                   = "if"
	KeyThen                 = "then"
	KeyElse                 = "else"
)

// SubSchema holds a sub schema
type SubSchema struct {
	Draft *Draft

	// basic SubSchema meta properties
	ID          *gojsonreference.JsonReference
	title       *string
	description *string

	Property string

	// Quick pass/fail for boolean schemas
	pass *bool

	// Types associated with the SubSchema
	Types jsonSchemaType

	// Reference url
	Ref *gojsonreference.JsonReference
	// Schema referenced
	RefSchema *SubSchema

	// hierarchy
	Parent                      *SubSchema
	ItemsChildren               []*SubSchema
	ItemsChildrenIsSingleSchema bool
	PropertiesChildren          []*SubSchema

	// validation : number / integer
	multipleOf       *big.Rat
	maximum          *big.Rat
	exclusiveMaximum *big.Rat
	minimum          *big.Rat
	exclusiveMinimum *big.Rat

	// validation : string
	minLength *int
	maxLength *int
	pattern   *regexp.Regexp
	format    string

	// validation : object
	minProperties *int
	maxProperties *int
	required      []string

	dependencies         map[string]interface{}
	additionalProperties interface{}
	patternProperties    map[string]*SubSchema
	propertyNames        *SubSchema

	// validation : array
	minItems    *int
	maxItems    *int
	uniqueItems bool
	contains    *SubSchema

	additionalItems interface{}

	// validation : all
	_const *string //const is a golang keyword
	enum   []string

	// validation : SubSchema
	oneOf []*SubSchema
	AnyOf []*SubSchema
	AllOf []*SubSchema
	not   *SubSchema
	_if   *SubSchema // if/else are golang keywords
	_then *SubSchema
	_else *SubSchema
}
