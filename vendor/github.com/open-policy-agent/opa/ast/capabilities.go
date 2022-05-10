// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	caps "github.com/open-policy-agent/opa/capabilities"
	"github.com/open-policy-agent/opa/internal/wasm/sdk/opa/capabilities"
	"github.com/open-policy-agent/opa/util"
)

// Capabilities defines a structure containing data that describes the capabilities
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

// LoadCapabilitiesVersion loads a JSON serialized capabilities structure from the specific version.
func LoadCapabilitiesVersion(version string) (*Capabilities, error) {
	cvs, err := LoadCapabilitiesVersions()
	if err != nil {
		return nil, err
	}

	for _, cv := range cvs {
		if cv == version {
			cont, err := caps.FS.ReadFile(cv + ".json")
			if err != nil {
				return nil, err
			}

			return LoadCapabilitiesJSON(bytes.NewReader(cont))
		}

	}
	return nil, fmt.Errorf("no capabilities version found %v", version)
}

// LoadCapabilitiesFile loads a JSON serialized capabilities structure from a file.
func LoadCapabilitiesFile(file string) (*Capabilities, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return LoadCapabilitiesJSON(fd)
}

// LoadCapabilitiesVersions loads all capabilities versions
func LoadCapabilitiesVersions() ([]string, error) {
	ents, err := caps.FS.ReadDir(".")
	if err != nil {
		return nil, err
	}

	var capabilitiesVersions []string
	for _, ent := range ents {
		capabilitiesVersions = append(capabilitiesVersions, strings.Replace(ent.Name(), ".json", "", 1))
	}
	return capabilitiesVersions, nil
}
