// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package topdown provides low-level query evaluation support.
//
// The topdown implementation is a modified version of the standard top-down
// evaluation algorithm used in Datalog. References and comprehensions are
// evaluated eagerly while all other terms are evaluated lazily.
package topdown
