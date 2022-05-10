// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

// PageSize represents the WASM page size in bytes.
const PageSize = 65535

// Pages converts a byte size to Pages, rounding up as necessary.
func Pages(n uint32) uint32 {
	pages := n / PageSize
	if pages*PageSize == n {
		return pages
	}

	return pages + 1
}
