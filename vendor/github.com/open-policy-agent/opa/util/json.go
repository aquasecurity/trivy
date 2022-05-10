// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/ghodss/yaml"
)

// UnmarshalJSON parses the JSON encoded data and stores the result in the value
// pointed to by x.
//
// This function is intended to be used in place of the standard json.Marshal
// function when json.Number is required.
func UnmarshalJSON(bs []byte, x interface{}) (err error) {
	buf := bytes.NewBuffer(bs)
	decoder := NewJSONDecoder(buf)
	if err := decoder.Decode(x); err != nil {
		return err
	}

	// Since decoder.Decode validates only the first json structure in bytes,
	// check if decoder has more bytes to consume to validate whole input bytes.
	tok, err := decoder.Token()
	if tok != nil {
		return fmt.Errorf("error: invalid character '%s' after top-level value", tok)
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

// NewJSONDecoder returns a new decoder that reads from r.
//
// This function is intended to be used in place of the standard json.NewDecoder
// when json.Number is required.
func NewJSONDecoder(r io.Reader) *json.Decoder {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	return decoder
}

// MustUnmarshalJSON parse the JSON encoded data and returns the result.
//
// If the data cannot be decoded, this function will panic. This function is for
// test purposes.
func MustUnmarshalJSON(bs []byte) interface{} {
	var x interface{}
	if err := UnmarshalJSON(bs, &x); err != nil {
		panic(err)
	}
	return x
}

// MustMarshalJSON returns the JSON encoding of x
//
// If the data cannot be encoded, this function will panic. This function is for
// test purposes.
func MustMarshalJSON(x interface{}) []byte {
	bs, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	return bs
}

// RoundTrip encodes to JSON, and decodes the result again.
//
// Thereby, it is converting its argument to the representation expected by
// rego.Input and inmem's Write operations. Works with both references and
// values.
func RoundTrip(x *interface{}) error {
	bs, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return UnmarshalJSON(bs, x)
}

// Reference returns a pointer to its argument unless the argument already is
// a pointer. If the argument is **t, or ***t, etc, it will return *t.
//
// Used for preparing Go types (including pointers to structs) into values to be
// put through util.RoundTrip().
func Reference(x interface{}) *interface{} {
	var y interface{}
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.Ptr {
		return Reference(rv.Elem().Interface())
	}
	if rv.Kind() != reflect.Invalid {
		y = rv.Interface()
		return &y
	}
	return &x
}

// Unmarshal decodes a YAML or JSON value into the specified type.
func Unmarshal(bs []byte, v interface{}) error {
	bs, err := yaml.YAMLToJSON(bs)
	if err != nil {
		return err
	}
	return UnmarshalJSON(bs, v)
}
