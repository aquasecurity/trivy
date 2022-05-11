// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package jsonsaver

import (
	"bytes"
	"io"

	"github.com/spdx/tools-golang/jsonsaver/saver2v2"
	"github.com/spdx/tools-golang/spdx"
)

// Save2_2 takes an io.Writer and an SPDX Document (version 2.2),
// and writes it to the writer in json format. It returns error
// if any error is encountered.
func Save2_2(doc *spdx.Document2_2, w io.Writer) error {
	var b []byte
	buf := bytes.NewBuffer(b)
	err := saver2v2.RenderDocument2_2(doc, buf)
	if err != nil {
		return err
	}
	w.Write(buf.Bytes())
	return nil
}
