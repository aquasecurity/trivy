// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package ast

import (
	"fmt"
	"sort"
	"strings"
)

// Errors represents a series of errors encountered during parsing, compiling,
// etc.
type Errors []*Error

func (e Errors) Error() string {

	if len(e) == 0 {
		return "no error(s)"
	}

	if len(e) == 1 {
		return fmt.Sprintf("1 error occurred: %v", e[0].Error())
	}

	s := make([]string, len(e))
	for i, err := range e {
		s[i] = err.Error()
	}

	return fmt.Sprintf("%d errors occurred:\n%s", len(e), strings.Join(s, "\n"))
}

// Sort sorts the error slice by location. If the locations are equal then the
// error message is compared.
func (e Errors) Sort() {
	sort.Slice(e, func(i, j int) bool {
		a := e[i]
		b := e[j]

		if cmp := a.Location.Compare(b.Location); cmp != 0 {
			return cmp < 0
		}

		return a.Error() < b.Error()
	})
}

const (
	// ParseErr indicates an unclassified parse error occurred.
	ParseErr = "rego_parse_error"

	// CompileErr indicates an unclassified compile error occurred.
	CompileErr = "rego_compile_error"

	// TypeErr indicates a type error was caught.
	TypeErr = "rego_type_error"

	// UnsafeVarErr indicates an unsafe variable was found during compilation.
	UnsafeVarErr = "rego_unsafe_var_error"

	// RecursionErr indicates recursion was found during compilation.
	RecursionErr = "rego_recursion_error"
)

// IsError returns true if err is an AST error with code.
func IsError(code string, err error) bool {
	if err, ok := err.(*Error); ok {
		return err.Code == code
	}
	return false
}

// ErrorDetails defines the interface for detailed error messages.
type ErrorDetails interface {
	Lines() []string
}

// Error represents a single error caught during parsing, compiling, etc.
type Error struct {
	Code     string       `json:"code"`
	Message  string       `json:"message"`
	Location *Location    `json:"location,omitempty"`
	Details  ErrorDetails `json:"details,omitempty"`
}

func (e *Error) Error() string {

	var prefix string

	if e.Location != nil {

		if len(e.Location.File) > 0 {
			prefix += e.Location.File + ":" + fmt.Sprint(e.Location.Row)
		} else {
			prefix += fmt.Sprint(e.Location.Row) + ":" + fmt.Sprint(e.Location.Col)
		}
	}

	msg := fmt.Sprintf("%v: %v", e.Code, e.Message)

	if len(prefix) > 0 {
		msg = prefix + ": " + msg
	}

	if e.Details != nil {
		for _, line := range e.Details.Lines() {
			msg += "\n\t" + line
		}
	}

	return msg
}

// NewError returns a new Error object.
func NewError(code string, loc *Location, f string, a ...interface{}) *Error {
	return &Error{
		Code:     code,
		Location: loc,
		Message:  fmt.Sprintf(f, a...),
	}
}

var (
	errPartialRuleAssignOperator = fmt.Errorf("partial rules must use = operator (not := operator)")
	errFunctionAssignOperator    = fmt.Errorf("functions must use = operator (not := operator)")
)

func errTermAssignOperator(x interface{}) error {
	return fmt.Errorf("cannot assign to %v", TypeName(x))
}
