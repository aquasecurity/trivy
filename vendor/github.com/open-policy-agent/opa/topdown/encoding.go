// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	ghodss "github.com/ghodss/yaml"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/util"
)

func builtinJSONMarshal(a ast.Value) (ast.Value, error) {

	asJSON, err := ast.JSON(a)
	if err != nil {
		return nil, err
	}

	bs, err := json.Marshal(asJSON)
	if err != nil {
		return nil, err
	}

	return ast.String(string(bs)), nil
}

func builtinJSONUnmarshal(a ast.Value) (ast.Value, error) {

	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	var x interface{}

	if err := util.UnmarshalJSON([]byte(str), &x); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(x)
}

func builtinJSONIsValid(a ast.Value) (ast.Value, error) {

	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.Boolean(json.Valid([]byte(str))), nil
}

func builtinBase64Encode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(base64.StdEncoding.EncodeToString([]byte(str))), nil
}

func builtinBase64Decode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	result, err := base64.StdEncoding.DecodeString(string(str))
	return ast.String(result), err
}

func builtinBase64IsValid(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	_, err = base64.StdEncoding.DecodeString(string(str))
	return ast.Boolean(err == nil), nil
}

func builtinBase64UrlEncode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	return ast.String(base64.URLEncoding.EncodeToString([]byte(str))), nil
}

func builtinBase64UrlEncodeNoPad(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	return ast.String(base64.RawURLEncoding.EncodeToString([]byte(str))), nil
}

func builtinBase64UrlDecode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	s := string(str)

	// Some base64url encoders omit the padding at the end, so this case
	// corrects such representations using the method given in RFC 7515
	// Appendix C: https://tools.ietf.org/html/rfc7515#appendix-C
	if !strings.HasSuffix(s, "=") {
		switch len(s) % 4 {
		case 0:
		case 2:
			s += "=="
		case 3:
			s += "="
		default:
			return nil, fmt.Errorf("illegal base64url string: %s", s)
		}
	}
	result, err := base64.URLEncoding.DecodeString(s)
	return ast.String(result), err
}

func builtinURLQueryEncode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	return ast.String(url.QueryEscape(string(str))), nil
}

func builtinURLQueryDecode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	s, err := url.QueryUnescape(string(str))
	if err != nil {
		return nil, err
	}
	return ast.String(s), nil
}

var encodeObjectErr = builtins.NewOperandErr(1, "values must be string, array[string], or set[string]")

func builtinURLQueryEncodeObject(a ast.Value) (ast.Value, error) {
	asJSON, err := ast.JSON(a)
	if err != nil {
		return nil, err
	}

	inputs, ok := asJSON.(map[string]interface{})
	if !ok {
		return nil, builtins.NewOperandTypeErr(1, a, "object")
	}

	query := url.Values{}

	for k, v := range inputs {
		switch vv := v.(type) {
		case string:
			query.Set(k, vv)
		case []interface{}:
			for _, val := range vv {
				strVal, ok := val.(string)
				if !ok {
					return nil, encodeObjectErr
				}
				query.Add(k, strVal)
			}
		default:
			return nil, encodeObjectErr
		}
	}

	return ast.String(query.Encode()), nil
}

func builtinURLQueryDecodeObject(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	query, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	queryParams, err := url.ParseQuery(string(query))
	if err != nil {
		return err
	}

	queryObject := ast.NewObject()
	for k, v := range queryParams {
		paramsArray := make([]*ast.Term, len(v))
		for i, param := range v {
			paramsArray[i] = ast.StringTerm(param)
		}
		queryObject.Insert(ast.StringTerm(k), ast.ArrayTerm(paramsArray...))
	}

	return iter(ast.NewTerm(queryObject))
}

func builtinYAMLMarshal(a ast.Value) (ast.Value, error) {

	asJSON, err := ast.JSON(a)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	if err := encoder.Encode(asJSON); err != nil {
		return nil, err
	}

	bs, err := ghodss.JSONToYAML(buf.Bytes())
	if err != nil {
		return nil, err
	}

	return ast.String(string(bs)), nil
}

func builtinYAMLUnmarshal(a ast.Value) (ast.Value, error) {

	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	bs, err := ghodss.YAMLToJSON([]byte(str))
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(bs)
	decoder := util.NewJSONDecoder(buf)
	var val interface{}
	err = decoder.Decode(&val)
	if err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(val)
}

func builtinYAMLIsValid(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	var x interface{}
	err = ghodss.Unmarshal([]byte(str), &x)
	return ast.Boolean(err == nil), nil
}

func builtinHexEncode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	return ast.String(hex.EncodeToString([]byte(str))), nil
}

func builtinHexDecode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	val, err := hex.DecodeString(string(str))
	if err != nil {
		return nil, err
	}
	return ast.String(val), nil
}

func init() {
	RegisterFunctionalBuiltin1(ast.JSONMarshal.Name, builtinJSONMarshal)
	RegisterFunctionalBuiltin1(ast.JSONUnmarshal.Name, builtinJSONUnmarshal)
	RegisterFunctionalBuiltin1(ast.JSONIsValid.Name, builtinJSONIsValid)
	RegisterFunctionalBuiltin1(ast.Base64Encode.Name, builtinBase64Encode)
	RegisterFunctionalBuiltin1(ast.Base64Decode.Name, builtinBase64Decode)
	RegisterFunctionalBuiltin1(ast.Base64IsValid.Name, builtinBase64IsValid)
	RegisterFunctionalBuiltin1(ast.Base64UrlEncode.Name, builtinBase64UrlEncode)
	RegisterFunctionalBuiltin1(ast.Base64UrlEncodeNoPad.Name, builtinBase64UrlEncodeNoPad)
	RegisterFunctionalBuiltin1(ast.Base64UrlDecode.Name, builtinBase64UrlDecode)
	RegisterFunctionalBuiltin1(ast.URLQueryDecode.Name, builtinURLQueryDecode)
	RegisterFunctionalBuiltin1(ast.URLQueryEncode.Name, builtinURLQueryEncode)
	RegisterFunctionalBuiltin1(ast.URLQueryEncodeObject.Name, builtinURLQueryEncodeObject)
	RegisterBuiltinFunc(ast.URLQueryDecodeObject.Name, builtinURLQueryDecodeObject)
	RegisterFunctionalBuiltin1(ast.YAMLMarshal.Name, builtinYAMLMarshal)
	RegisterFunctionalBuiltin1(ast.YAMLUnmarshal.Name, builtinYAMLUnmarshal)
	RegisterFunctionalBuiltin1(ast.YAMLIsValid.Name, builtinYAMLIsValid)
	RegisterFunctionalBuiltin1(ast.HexEncode.Name, builtinHexEncode)
	RegisterFunctionalBuiltin1(ast.HexDecode.Name, builtinHexDecode)
}
