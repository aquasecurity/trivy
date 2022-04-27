// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"io"
	"sort"

	"github.com/open-policy-agent/opa/internal/wasm/sdk/opa/capabilities"
	"github.com/open-policy-agent/opa/util"
)

// Capabilities defines a structure containing data that describes the capablilities
// or features supported by a particular version of OPA.
type Capabilities struct {
	Builtins        []*Builtin       `json:"builtins"`
	FutureKeywords  []string         `json:"future_keywords"`
	WasmABIVersions []WasmABIVersion `json:"wasm_abi_versions"`

	// allow_net is an array of hostnames or IP addresses, that an OPA instance is
	// allowed to connect to.
	// If omitted, ANY host can be connected to. If empty, NO host can be connected to.
	// As of now, this only controls fetching remote refs for using JSON Schemas in
	// the type checker.
	// TODO(sr): support ports to further restrict connection peers
	// TODO(sr): support restricting `http.send` using the same mechanism (see https://github.com/open-policy-agent/opa/issues/3665)
	AllowNet []string `json:"allow_net,omitempty"`
}

// WasmABIVersion captures the Wasm ABI version. Its `Minor` version is indicating
// backwards-compatible changes.
type WasmABIVersion struct {
	Version int `json:"version"`
	Minor   int `json:"minor_version"`
}

// CapabilitiesForThisVersion returns the capabilities of this version of OPA.
func CapabilitiesForThisVersion() *Capabilities {
	f := &Capabilities{}

	for _, vers := range capabilities.ABIVersions() {
		f.WasmABIVersions = append(f.WasmABIVersions, WasmABIVersion{Version: vers[0], Minor: vers[1]})
	}

	f.Builtins = append(f.Builtins, Builtins...)
	sort.Slice(f.Builtins, func(i, j int) bool {
		return f.Builtins[i].Name < f.Builtins[j].Name
	})

	for kw := range futureKeywords {
		f.FutureKeywords = append(f.FutureKeywords, kw)
	}
	sort.Strings(f.FutureKeywords)

	return f
}

// LoadCapabilitiesJSON loads a JSON serialized capabilities structure from the reader r.
func LoadCapabilitiesJSON(r io.Reader) (*Capabilities, error) {
	d := util.NewJSONDecoder(r)
	var c Capabilities
	return &c, d.Decode(&c)
}
