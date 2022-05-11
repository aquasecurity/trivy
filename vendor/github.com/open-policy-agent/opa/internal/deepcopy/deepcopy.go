// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package deepcopy

// DeepCopy performs a recursive deep copy for nested slices/maps and
// returns the copied object. Supports []interface{}
// and map[string]interface{} only
func DeepCopy(val interface{}) interface{} {
	switch val := val.(type) {
	case []interface{}:
		cpy := make([]interface{}, len(val))
		for i := range cpy {
			cpy[i] = DeepCopy(val[i])
		}
		return cpy
	case map[string]interface{}:
		return Map(val)
	default:
		return val
	}
}

func Map(val map[string]interface{}) map[string]interface{} {
	cpy := make(map[string]interface{}, len(val))
	for k := range val {
		cpy[k] = DeepCopy(val[k])
	}
	return cpy
}
