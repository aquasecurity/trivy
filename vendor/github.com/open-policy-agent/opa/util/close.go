// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"io"
	"io/ioutil"
	"net/http"
)

// Close reads the remaining bytes from the response and then closes it to
// ensure that the connection is freed. If the body is not read and closed, a
// leak can occur.
func Close(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
			return
		}
		resp.Body.Close()
	}
}
