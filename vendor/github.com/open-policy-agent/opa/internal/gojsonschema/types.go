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
// description      Contains const types for schema and JSON.
//
// created          28-02-2013

package gojsonschema

// Type constants
const (
	TypeArray   = `array`
	TypeBoolean = `boolean`
	TypeInteger = `integer`
	TypeNumber  = `number`
	TypeNull    = `null`
	TypeObject  = `object`
	TypeString  = `string`
)

// JSONTypes hosts the list of type that are supported in JSON
var JSONTypes []string

// SchemaTypes Hosts The List Of Type That Are Supported In Schemas
var SchemaTypes []string

func init() {
	JSONTypes = []string{
		TypeArray,
		TypeBoolean,
		TypeInteger,
		TypeNumber,
		TypeNull,
		TypeObject,
		TypeString}

	SchemaTypes = []string{
		TypeArray,
		TypeBoolean,
		TypeInteger,
		TypeNumber,
		TypeObject,
		TypeString}
}
