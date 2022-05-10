// This file is part of CycloneDX Go
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Niklas Düster. All Rights Reserved.

package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
)

type BOMEncoder interface {
	Encode(*BOM) error
	SetPretty(bool)
}

func NewBOMEncoder(writer io.Writer, format BOMFileFormat) BOMEncoder {
	if format == BOMFileFormatJSON {
		return &jsonBOMEncoder{writer: writer}
	}
	return &xmlBOMEncoder{writer: writer}
}

type jsonBOMEncoder struct {
	writer io.Writer
	pretty bool
}

func (j jsonBOMEncoder) Encode(bom *BOM) error {
	encoder := json.NewEncoder(j.writer)
	if j.pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(bom)
}

func (j *jsonBOMEncoder) SetPretty(pretty bool) {
	j.pretty = pretty
}

type xmlBOMEncoder struct {
	writer io.Writer
	pretty bool
}

func (x xmlBOMEncoder) Encode(bom *BOM) error {
	if _, err := fmt.Fprintf(x.writer, xml.Header); err != nil {
		return err
	}

	encoder := xml.NewEncoder(x.writer)
	if x.pretty {
		encoder.Indent("", "  ")
	}
	return encoder.Encode(bom)
}

func (x *xmlBOMEncoder) SetPretty(pretty bool) {
	x.pretty = pretty
}
