// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

//go:build go1.16
// +build go1.16

package capabilities

import (
	"embed"
)

// FS contains the embedded capabilities/ directory of the built version,
// which has all the capabilities of previous versions:
// "v0.18.0.json" contains the capabilities JSON of version v0.18.0, etc
//go:embed *.json
var FS embed.FS
