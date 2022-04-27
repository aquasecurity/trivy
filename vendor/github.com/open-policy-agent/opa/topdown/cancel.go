// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"sync/atomic"
)

// Cancel defines the interface for cancelling topdown queries. Cancel
// operations are thread-safe and idempotent.
type Cancel interface {
	Cancel()
	Cancelled() bool
}

type cancel struct {
	flag int32
}

// NewCancel returns a new Cancel object.
func NewCancel() Cancel {
	return &cancel{}
}

func (c *cancel) Cancel() {
	atomic.StoreInt32(&c.flag, 1)
}

func (c *cancel) Cancelled() bool {
	return atomic.LoadInt32(&c.flag) != 0
}
