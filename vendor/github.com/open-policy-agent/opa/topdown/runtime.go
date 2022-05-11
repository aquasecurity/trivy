// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

func builtinOPARuntime(bctx BuiltinContext, _ []*ast.Term, iter func(*ast.Term) error) error {

	if bctx.Runtime == nil {
		return iter(ast.ObjectTerm())
	}

	if bctx.Runtime.Get(ast.StringTerm("config")) != nil {
		iface, err := ast.ValueToInterface(bctx.Runtime.Value, illegalResolver{})
		if err != nil {
			return err
		}
		if object, ok := iface.(map[string]interface{}); ok {
			if cfgRaw, ok := object["config"]; ok {
				if config, ok := cfgRaw.(map[string]interface{}); ok {
					configPurged, err := activeConfig(config)
					if err != nil {
						return err
					}
					object["config"] = configPurged
					value, err := ast.InterfaceToValue(object)
					if err != nil {
						return err
					}
					return iter(ast.NewTerm(value))
				}
			}
		}
	}

	return iter(bctx.Runtime)
}

func init() {
	RegisterBuiltinFunc(ast.OPARuntime.Name, builtinOPARuntime)
}

func activeConfig(config map[string]interface{}) (interface{}, error) {

	if config["services"] != nil {
		err := removeServiceCredentials(config["services"])
		if err != nil {
			return nil, err
		}
	}

	if config["keys"] != nil {
		err := removeCryptoKeys(config["keys"])
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

func removeServiceCredentials(x interface{}) error {

	switch x := x.(type) {
	case []interface{}:
		for _, v := range x {
			err := removeKey(v, "credentials")
			if err != nil {
				return err
			}
		}

	case map[string]interface{}:
		for _, v := range x {
			err := removeKey(v, "credentials")
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("illegal service config type: %T", x)
	}

	return nil
}

func removeCryptoKeys(x interface{}) error {

	switch x := x.(type) {
	case map[string]interface{}:
		for _, v := range x {
			err := removeKey(v, "key", "private_key")
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("illegal keys config type: %T", x)
	}

	return nil
}

func removeKey(x interface{}, keys ...string) error {
	val, ok := x.(map[string]interface{})
	if !ok {
		return fmt.Errorf("type assertion error")
	}

	for _, key := range keys {
		delete(val, key)
	}

	return nil
}

type illegalResolver struct{}

func (illegalResolver) Resolve(ref ast.Ref) (interface{}, error) {
	return nil, fmt.Errorf("illegal value: %v", ref)
}
