// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"strings"
)

// EnumFlag implements the pflag.Value interface to provide enumerated command
// line parameter values.
type EnumFlag struct {
	defaultValue string
	vs           []string
	i            int
}

// NewEnumFlag returns a new EnumFlag that has a defaultValue and vs enumerated
// values.
func NewEnumFlag(defaultValue string, vs []string) *EnumFlag {
	f := &EnumFlag{
		i:            -1,
		vs:           vs,
		defaultValue: defaultValue,
	}
	return f
}

// Type returns the valid enumeration values.
func (f *EnumFlag) Type() string {
	return "{" + strings.Join(f.vs, ",") + "}"
}

// String returns the EnumValue's value as string.
func (f *EnumFlag) String() string {
	if f.i == -1 {
		return f.defaultValue
	}
	return f.vs[f.i]
}

// IsSet will return true if the EnumFlag has been set.
func (f *EnumFlag) IsSet() bool {
	return f.i != -1
}

// Set sets the enum value. If s is not a valid enum value, an error is
// returned.
func (f *EnumFlag) Set(s string) error {
	for i := range f.vs {
		if f.vs[i] == s {
			f.i = i
			return nil
		}
	}
	return fmt.Errorf("must be one of %v", f.Type())
}
