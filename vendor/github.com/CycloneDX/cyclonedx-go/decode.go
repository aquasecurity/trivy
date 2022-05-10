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
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"io"
)

type BOMDecoder interface {
	Decode(bom *BOM) error
}

func NewBOMDecoder(reader io.Reader, format BOMFileFormat) BOMDecoder {
	if format == BOMFileFormatJSON {
		return &jsonBOMDecoder{reader: reader}
	}
	return &xmlBOMDecoder{reader: reader}
}

type jsonBOMDecoder struct {
	reader io.Reader
}

func (j jsonBOMDecoder) Decode(bom *BOM) error {
	return json.NewDecoder(j.reader).Decode(bom)
}

type xmlBOMDecoder struct {
	reader io.Reader
}

func (x xmlBOMDecoder) Decode(bom *BOM) error {
	return xml.NewDecoder(x.reader).Decode(bom)
}
