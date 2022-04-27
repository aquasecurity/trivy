// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package storage

import (
	"context"

	"github.com/open-policy-agent/opa/metrics"
)

// Transaction defines the interface that identifies a consistent snapshot over
// the policy engine's storage layer.
type Transaction interface {
	ID() uint64
}

// Store defines the interface for the storage layer's backend.
type Store interface {
	Trigger
	Policy

	// NewTransaction is called create a new transaction in the store.
	NewTransaction(context.Context, ...TransactionParams) (Transaction, error)

	// Read is called to fetch a document referred to by path.
	Read(context.Context, Transaction, Path) (interface{}, error)

	// Write is called to modify a document referred to by path.
	Write(context.Context, Transaction, PatchOp, Path, interface{}) error

	// Commit is called to finish the transaction. If Commit returns an error, the
	// transaction must be automatically aborted by the Store implementation.
	Commit(context.Context, Transaction) error

	// Abort is called to cancel the transaction.
	Abort(context.Context, Transaction)
}

// MakeDirer defines the interface a Store could realize to override the
// generic MakeDir functionality in storage.MakeDir
type MakeDirer interface {
	MakeDir(context.Context, Transaction, Path) error
}

// TransactionParams describes a new transaction.
type TransactionParams struct {

	// Write indicates if this transaction will perform any write operations.
	Write bool

	// Context contains key/value pairs passed to triggers.
	Context *Context
}

// Context is a simple container for key/value pairs.
type Context struct {
	values map[interface{}]interface{}
}

// NewContext returns a new context object.
func NewContext() *Context {
	return &Context{
		values: map[interface{}]interface{}{},
	}
}

// Get returns the key value in the context.
func (ctx *Context) Get(key interface{}) interface{} {
	if ctx == nil {
		return nil
	}
	return ctx.values[key]
}

// Put adds a key/value pair to the context.
func (ctx *Context) Put(key, value interface{}) {
	ctx.values[key] = value
}

var metricsKey = struct{}{}

// WithMetrics allows passing metrics via the Context.
// It puts the metrics object in the ctx, and returns the same
// ctx (not a copy) for convenience.
func (ctx *Context) WithMetrics(m metrics.Metrics) *Context {
	ctx.values[metricsKey] = m
	return ctx
}

// Metrics() allows using a Context's metrics. Returns nil if metrics
// were not attached to the Context.
func (ctx *Context) Metrics() metrics.Metrics {
	if m, ok := ctx.values[metricsKey]; ok {
		if met, ok := m.(metrics.Metrics); ok {
			return met
		}
	}
	return nil
}

// WriteParams specifies the TransactionParams for a write transaction.
var WriteParams = TransactionParams{
	Write: true,
}

// PatchOp is the enumeration of supposed modifications.
type PatchOp int

// Patch supports add, remove, and replace operations.
const (
	AddOp     PatchOp = iota
	RemoveOp          = iota
	ReplaceOp         = iota
)

// WritesNotSupported provides a default implementation of the write
// interface which may be used if the backend does not support writes.
type WritesNotSupported struct{}

func (WritesNotSupported) Write(context.Context, Transaction, PatchOp, Path, interface{}) error {
	return writesNotSupportedError()
}

// Policy defines the interface for policy module storage.
type Policy interface {
	ListPolicies(context.Context, Transaction) ([]string, error)
	GetPolicy(context.Context, Transaction, string) ([]byte, error)
	UpsertPolicy(context.Context, Transaction, string, []byte) error
	DeletePolicy(context.Context, Transaction, string) error
}

// PolicyNotSupported provides a default implementation of the policy interface
// which may be used if the backend does not support policy storage.
type PolicyNotSupported struct{}

// ListPolicies always returns a PolicyNotSupportedErr.
func (PolicyNotSupported) ListPolicies(context.Context, Transaction) ([]string, error) {
	return nil, policyNotSupportedError()
}

// GetPolicy always returns a PolicyNotSupportedErr.
func (PolicyNotSupported) GetPolicy(context.Context, Transaction, string) ([]byte, error) {
	return nil, policyNotSupportedError()
}

// UpsertPolicy always returns a PolicyNotSupportedErr.
func (PolicyNotSupported) UpsertPolicy(context.Context, Transaction, string, []byte) error {
	return policyNotSupportedError()
}

// DeletePolicy always returns a PolicyNotSupportedErr.
func (PolicyNotSupported) DeletePolicy(context.Context, Transaction, string) error {
	return policyNotSupportedError()
}

// PolicyEvent describes a change to a policy.
type PolicyEvent struct {
	ID      string
	Data    []byte
	Removed bool
}

// DataEvent describes a change to a base data document.
type DataEvent struct {
	Path    Path
	Data    interface{}
	Removed bool
}

// TriggerEvent describes the changes that caused the trigger to be invoked.
type TriggerEvent struct {
	Policy  []PolicyEvent
	Data    []DataEvent
	Context *Context
}

// IsZero returns true if the TriggerEvent indicates no changes occurred. This
// function is primarily for test purposes.
func (e TriggerEvent) IsZero() bool {
	return !e.PolicyChanged() && !e.DataChanged()
}

// PolicyChanged returns true if the trigger was caused by a policy change.
func (e TriggerEvent) PolicyChanged() bool {
	return len(e.Policy) > 0
}

// DataChanged returns true if the trigger was caused by a data change.
func (e TriggerEvent) DataChanged() bool {
	return len(e.Data) > 0
}

// TriggerConfig contains the trigger registration configuration.
type TriggerConfig struct {

	// OnCommit is invoked when a transaction is successfully committed. The
	// callback is invoked with a handle to the write transaction that
	// successfully committed before other clients see the changes.
	OnCommit func(context.Context, Transaction, TriggerEvent)
}

// Trigger defines the interface that stores implement to register for change
// notifications when the store is changed.
type Trigger interface {
	Register(context.Context, Transaction, TriggerConfig) (TriggerHandle, error)
}

// TriggersNotSupported provides default implementations of the Trigger
// interface which may be used if the backend does not support triggers.
type TriggersNotSupported struct{}

// Register always returns an error indicating triggers are not supported.
func (TriggersNotSupported) Register(context.Context, Transaction, TriggerConfig) (TriggerHandle, error) {
	return nil, triggersNotSupportedError()
}

// TriggerHandle defines the interface that can be used to unregister triggers that have
// been registered on a Store.
type TriggerHandle interface {
	Unregister(context.Context, Transaction)
}
