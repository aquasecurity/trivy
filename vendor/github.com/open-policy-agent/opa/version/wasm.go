// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package version

import "github.com/open-policy-agent/opa/internal/rego/opa"

// WasmRuntimeAvailable indicates if a wasm runtime is available in this OPA.
func WasmRuntimeAvailable() bool {
	_, err := opa.LookupEngine("wasm")
	return err == nil
}
