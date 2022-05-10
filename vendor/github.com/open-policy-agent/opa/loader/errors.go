// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package loader

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// Errors is a wrapper for multiple loader errors.
type Errors []error

func (e Errors) Error() string {
	if len(e) == 0 {
		return "no error(s)"
	}
	if len(e) == 1 {
		return "1 error occurred during loading: " + e[0].Error()
	}
	buf := make([]string, len(e))
	for i := range buf {
		buf[i] = e[i].Error()
	}
	return fmt.Sprintf("%v errors occurred during loading:\n", len(e)) + strings.Join(buf, "\n")
}

func (e *Errors) add(err error) {
	if errs, ok := err.(ast.Errors); ok {
		for i := range errs {
			*e = append(*e, errs[i])
		}
	} else {
		*e = append(*e, err)
	}
}

type unsupportedDocumentType string

func (path unsupportedDocumentType) Error() string {
	return string(path) + ": bad document type"
}

type unrecognizedFile string

func (path unrecognizedFile) Error() string {
	return string(path) + ": can't recognize file type"
}

func isUnrecognizedFile(err error) bool {
	_, ok := err.(unrecognizedFile)
	return ok
}

type mergeError string

func (e mergeError) Error() string {
	return string(e) + ": merge error"
}
