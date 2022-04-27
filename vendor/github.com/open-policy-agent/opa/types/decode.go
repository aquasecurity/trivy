// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/util"
)

const (
	typeNull     = "null"
	typeBoolean  = "boolean"
	typeNumber   = "number"
	typeString   = "string"
	typeArray    = "array"
	typeSet      = "set"
	typeObject   = "object"
	typeAny      = "any"
	typeFunction = "function"
)

// Unmarshal deserializes bs and returns the resulting type.
func Unmarshal(bs []byte) (result Type, err error) {

	var hint rawtype

	if err = util.UnmarshalJSON(bs, &hint); err == nil {
		switch hint.Type {
		case typeNull:
			result = NewNull()
		case typeBoolean:
			result = NewBoolean()
		case typeNumber:
			result = NewNumber()
		case typeString:
			result = NewString()
		case typeArray:
			var arr rawarray
			if err = util.UnmarshalJSON(bs, &arr); err == nil {
				var err error
				var static []Type
				var dynamic Type
				if static, err = unmarshalSlice(arr.Static); err != nil {
					return nil, err
				}
				if len(arr.Dynamic) != 0 {
					if dynamic, err = Unmarshal(arr.Dynamic); err != nil {
						return nil, err
					}
				}
				result = NewArray(static, dynamic)
			}
		case typeObject:
			var obj rawobject
			if err = util.UnmarshalJSON(bs, &obj); err == nil {
				var err error
				var static []*StaticProperty
				var dynamic *DynamicProperty
				if static, err = unmarshalStaticPropertySlice(obj.Static); err != nil {
					return nil, err
				}
				if dynamic, err = unmarshalDynamicProperty(obj.Dynamic); err != nil {
					return nil, err
				}
				result = NewObject(static, dynamic)
			}
		case typeSet:
			var set rawset
			if err = util.UnmarshalJSON(bs, &set); err == nil {
				var of Type
				if of, err = Unmarshal(set.Of); err == nil {
					result = NewSet(of)
				}
			}
		case typeAny:
			var any rawunion
			if err = util.UnmarshalJSON(bs, &any); err == nil {
				var of []Type
				if of, err = unmarshalSlice(any.Of); err == nil {
					result = NewAny(of...)
				}
			}
		case typeFunction:
			var decl rawdecl
			if err = util.UnmarshalJSON(bs, &decl); err == nil {
				args, err := unmarshalSlice(decl.Args)
				if err != nil {
					return nil, err
				}
				var ret Type
				if len(decl.Result) > 0 {
					ret, err = Unmarshal(decl.Result)
					if err != nil {
						return nil, err
					}
				}
				if len(decl.Variadic) > 0 {
					varargs, err := Unmarshal(decl.Variadic)
					if err != nil {
						return nil, err
					}
					result = NewVariadicFunction(args, varargs, ret)
				} else {
					result = NewFunction(args, ret)
				}
			}
		default:
			err = fmt.Errorf("unsupported type '%v'", hint.Type)
		}
	}

	return result, err
}

type rawtype struct {
	Type string `json:"type"`
}

type rawarray struct {
	Static  []json.RawMessage `json:"static"`
	Dynamic json.RawMessage   `json:"dynamic"`
}

type rawobject struct {
	Static  []rawstaticproperty `json:"static"`
	Dynamic rawdynamicproperty  `json:"dynamic"`
}

type rawstaticproperty struct {
	Key   interface{}     `json:"key"`
	Value json.RawMessage `json:"value"`
}

type rawdynamicproperty struct {
	Key   json.RawMessage `json:"key"`
	Value json.RawMessage `json:"value"`
}

type rawset struct {
	Of json.RawMessage `json:"of"`
}

type rawunion struct {
	Of []json.RawMessage `json:"of"`
}

type rawdecl struct {
	Args     []json.RawMessage `json:"args"`
	Result   json.RawMessage   `json:"result"`
	Variadic json.RawMessage   `json:"variadic"`
}

func unmarshalSlice(elems []json.RawMessage) (result []Type, err error) {
	result = make([]Type, len(elems))
	for i := range elems {
		if result[i], err = Unmarshal(elems[i]); err != nil {
			return nil, err
		}
	}
	return result, err
}

func unmarshalStaticPropertySlice(elems []rawstaticproperty) (result []*StaticProperty, err error) {
	result = make([]*StaticProperty, len(elems))
	for i := range elems {
		value, err := Unmarshal(elems[i].Value)
		if err != nil {
			return nil, err
		}
		result[i] = NewStaticProperty(elems[i].Key, value)
	}
	return result, err
}

func unmarshalDynamicProperty(x rawdynamicproperty) (result *DynamicProperty, err error) {
	if len(x.Key) == 0 {
		return nil, nil
	}
	var key Type
	if key, err = Unmarshal(x.Key); err == nil {
		var value Type
		if value, err = Unmarshal(x.Value); err == nil {
			return NewDynamicProperty(key, value), nil
		}
	}
	return nil, err
}
