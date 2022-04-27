// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package storage

import (
	"context"
)

// NewTransactionOrDie is a helper function to create a new transaction. If the
// storage layer cannot create a new transaction, this function will panic. This
// function should only be used for tests.
func NewTransactionOrDie(ctx context.Context, store Store, params ...TransactionParams) Transaction {
	txn, err := store.NewTransaction(ctx, params...)
	if err != nil {
		panic(err)
	}
	return txn
}

// ReadOne is a convenience function to read a single value from the provided Store. It
// will create a new Transaction to perform the read with, and clean up after itself
// should an error occur.
func ReadOne(ctx context.Context, store Store, path Path) (interface{}, error) {
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Abort(ctx, txn)

	return store.Read(ctx, txn, path)
}

// WriteOne is a convenience function to write a single value to the provided Store. It
// will create a new Transaction to perform the write with, and clean up after itself
// should an error occur.
func WriteOne(ctx context.Context, store Store, op PatchOp, path Path, value interface{}) error {
	txn, err := store.NewTransaction(ctx, WriteParams)
	if err != nil {
		return err
	}

	if err := store.Write(ctx, txn, op, path, value); err != nil {
		store.Abort(ctx, txn)
		return err
	}

	return store.Commit(ctx, txn)
}

// MakeDir inserts an empty object at path. If the parent path does not exist,
// MakeDir will create it recursively.
func MakeDir(ctx context.Context, store Store, txn Transaction, path Path) error {

	// Allow the Store implementation to deal with this in its own way.
	if md, ok := store.(MakeDirer); ok {
		return md.MakeDir(ctx, txn, path)
	}

	if len(path) == 0 {
		return nil
	}

	node, err := store.Read(ctx, txn, path)
	if err != nil {
		if !IsNotFound(err) {
			return err
		}

		if err := MakeDir(ctx, store, txn, path[:len(path)-1]); err != nil {
			return err
		}

		return store.Write(ctx, txn, AddOp, path, map[string]interface{}{})
	}

	if _, ok := node.(map[string]interface{}); ok {
		return nil
	}
	return writeConflictError(path)
}

// Txn is a convenience function that executes f inside a new transaction
// opened on the store. If the function returns an error, the transaction is
// aborted and the error is returned. Otherwise, the transaction is committed
// and the result of the commit is returned.
func Txn(ctx context.Context, store Store, params TransactionParams, f func(Transaction) error) error {

	txn, err := store.NewTransaction(ctx, params)
	if err != nil {
		return err
	}

	if err := f(txn); err != nil {
		store.Abort(ctx, txn)
		return err
	}

	return store.Commit(ctx, txn)
}

// NonEmpty returns a function that tests if a path is non-empty. A
// path is non-empty if a Read on the path returns a value or a Read
// on any of the path prefixes returns a non-object value.
func NonEmpty(ctx context.Context, store Store, txn Transaction) func([]string) (bool, error) {
	return func(path []string) (bool, error) {
		if _, err := store.Read(ctx, txn, Path(path)); err == nil {
			return true, nil
		} else if !IsNotFound(err) {
			return false, err
		}
		for i := len(path) - 1; i > 0; i-- {
			val, err := store.Read(ctx, txn, Path(path[:i]))
			if err != nil && !IsNotFound(err) {
				return false, err
			} else if err == nil {
				if _, ok := val.(map[string]interface{}); ok {
					return false, nil
				}
				return true, nil
			}
		}
		return false, nil
	}
}
