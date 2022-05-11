// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package jsonloader

import (
	"bytes"
	"io"

	parser2v2 "github.com/spdx/tools-golang/jsonloader/parser2v2"
	"github.com/spdx/tools-golang/spdx"
)

// Takes in a file Reader and returns the pertaining spdx document
// or the error if any is encountered while setting the doc.
func Load2_2(content io.Reader) (*spdx.Document2_2, error) {
	//convert io.Reader to a slice of bytes and call the parser
	buf := new(bytes.Buffer)
	buf.ReadFrom(content)
	var doc, err = parser2v2.Load2_2(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return doc, nil
}
