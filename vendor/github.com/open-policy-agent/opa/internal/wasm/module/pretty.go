// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package module

import (
	"encoding/hex"
	"fmt"
	"io"
)

// PrettyOption defines options for controlling pretty printing.
type PrettyOption struct {
	Contents bool // show raw byte content of data+code sections.
}

// Pretty writes a human-readable representation of m to w.
func Pretty(w io.Writer, m *Module, opts ...PrettyOption) {
	fmt.Fprintln(w, "version:", m.Version)
	fmt.Fprintln(w, "types:")
	for _, fn := range m.Type.Functions {
		fmt.Fprintln(w, "  -", fn)
	}
	fmt.Fprintln(w, "imports:")
	for i, imp := range m.Import.Imports {
		if imp.Descriptor.Kind() == FunctionImportType {
			fmt.Printf("  - [%d] %v\n", i, imp)
		} else {
			fmt.Fprintln(w, "  -", imp)
		}
	}
	fmt.Fprintln(w, "functions:")
	for _, fn := range m.Function.TypeIndices {
		if fn >= uint32(len(m.Type.Functions)) {
			fmt.Fprintln(w, "  -", "???")
		} else {
			fmt.Fprintln(w, "  -", m.Type.Functions[fn])
		}
	}
	fmt.Fprintln(w, "exports:")
	for _, exp := range m.Export.Exports {
		fmt.Fprintln(w, "  -", exp)
	}
	fmt.Fprintln(w, "code:")
	for _, seg := range m.Code.Segments {
		fmt.Fprintln(w, "  -", seg)
	}
	fmt.Fprintln(w, "data:")
	for _, seg := range m.Data.Segments {
		fmt.Fprintln(w, "  -", seg)
	}
	if len(opts) == 0 {
		return
	}
	fmt.Fprintln(w)
	for _, opt := range opts {
		if opt.Contents {
			newline := false
			if len(m.Data.Segments) > 0 {
				fmt.Fprintln(w, "data section:")
				for _, seg := range m.Data.Segments {
					if newline {
						fmt.Fprintln(w)
					}
					fmt.Fprintln(w, hex.Dump(seg.Init))
					newline = true
				}
				newline = false
			}
			if len(m.Code.Segments) > 0 {
				fmt.Fprintln(w, "code section:")
				for _, seg := range m.Code.Segments {
					if newline {
						fmt.Fprintln(w)
					}
					fmt.Fprintln(w, hex.Dump(seg.Code))
					newline = true
				}
				newline = false
			}
		}
	}
}
