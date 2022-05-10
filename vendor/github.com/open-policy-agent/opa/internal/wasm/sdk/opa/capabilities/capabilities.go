// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// +build opa_wasm generate

package capabilities

// ABIVersions returns the ABI versions that this SDK supports
func ABIVersions() [][2]int {
	return [][2]int{{1, 1}, {1, 2}}
}
