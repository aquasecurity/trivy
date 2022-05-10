// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

//go:build !opa_wasm && !generate
// +build !opa_wasm,!generate

package capabilities

// ABIVersions returns the supported Wasm ABI versions for this
// build: none
func ABIVersions() [][2]int {
	return nil
}
