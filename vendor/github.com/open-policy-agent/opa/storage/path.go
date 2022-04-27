// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package storage

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// Path refers to a document in storage.
type Path []string

// ParsePath returns a new path for the given str.
func ParsePath(str string) (path Path, ok bool) {
	if len(str) == 0 {
		return nil, false
	}
	if str[0] != '/' {
		return nil, false
	}
	if len(str) == 1 {
		return Path{}, true
	}
	parts := strings.Split(str[1:], "/")
	return parts, true
}

// ParsePathEscaped returns a new path for the given escaped str.
func ParsePathEscaped(str string) (path Path, ok bool) {
	path, ok = ParsePath(str)
	if !ok {
		return
	}
	for i := range path {
		segment, err := url.PathUnescape(path[i])
		if err == nil {
			path[i] = segment
		}
	}
	return
}

// NewPathForRef returns a new path for the given ref.
func NewPathForRef(ref ast.Ref) (path Path, err error) {

	if len(ref) == 0 {
		return nil, fmt.Errorf("empty reference (indicates error in caller)")
	}

	if len(ref) == 1 {
		return Path{}, nil
	}

	path = make(Path, 0, len(ref)-1)

	for _, term := range ref[1:] {
		switch v := term.Value.(type) {
		case ast.String:
			path = append(path, string(v))
		case ast.Number:
			path = append(path, v.String())
		case ast.Boolean, ast.Null:
			return nil, &Error{
				Code:    NotFoundErr,
				Message: fmt.Sprintf("%v: does not exist", ref),
			}
		case *ast.Array, ast.Object, ast.Set:
			return nil, fmt.Errorf("composites cannot be base document keys: %v", ref)
		default:
			return nil, fmt.Errorf("unresolved reference (indicates error in caller): %v", ref)
		}
	}

	return path, nil
}

// Compare performs lexigraphical comparison on p and other and returns -1 if p
// is less than other, 0 if p is equal to other, or 1 if p is greater than
// other.
func (p Path) Compare(other Path) (cmp int) {
	min := len(p)
	if len(other) < min {
		min = len(other)
	}
	for i := 0; i < min; i++ {
		if cmp := strings.Compare(p[i], other[i]); cmp != 0 {
			return cmp
		}
	}
	if len(p) < len(other) {
		return -1
	}
	if len(p) == len(other) {
		return 0
	}
	return 1
}

// Equal returns true if p is the same as other.
func (p Path) Equal(other Path) bool {
	return p.Compare(other) == 0
}

// HasPrefix returns true if p starts with other.
func (p Path) HasPrefix(other Path) bool {
	if len(other) > len(p) {
		return false
	}
	for i := range other {
		if p[i] != other[i] {
			return false
		}
	}
	return true
}

// Ref returns a ref that represents p rooted at head.
func (p Path) Ref(head *ast.Term) (ref ast.Ref) {
	ref = make(ast.Ref, len(p)+1)
	ref[0] = head
	for i := range p {
		idx, err := strconv.ParseInt(p[i], 10, 64)
		if err == nil {
			ref[i+1] = ast.UIntNumberTerm(uint64(idx))
		} else {
			ref[i+1] = ast.StringTerm(p[i])
		}
	}
	return ref
}

func (p Path) String() string {
	buf := make([]string, len(p))
	for i := range buf {
		buf[i] = url.PathEscape(p[i])
	}
	return "/" + strings.Join(buf, "/")
}

// MustParsePath returns a new Path for s. If s cannot be parsed, this function
// will panic. This is mostly for test purposes.
func MustParsePath(s string) Path {
	path, ok := ParsePath(s)
	if !ok {
		panic(s)
	}
	return path
}
