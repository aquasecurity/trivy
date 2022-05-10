// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package cache defines the inter-query cache interface that can cache data across queries
package cache

import (
	"container/list"

	"github.com/open-policy-agent/opa/ast"

	"sync"

	"github.com/open-policy-agent/opa/util"
)

const (
	defaultMaxSizeBytes = int64(0) // unlimited
)

// Config represents the configuration of the inter-query cache.
type Config struct {
	InterQueryBuiltinCache InterQueryBuiltinCacheConfig `json:"inter_query_builtin_cache"`
}

// InterQueryBuiltinCacheConfig represents the configuration of the inter-query cache that built-in functions can utilize.
type InterQueryBuiltinCacheConfig struct {
	MaxSizeBytes *int64 `json:"max_size_bytes,omitempty"`
}

// ParseCachingConfig returns the config for the inter-query cache.
func ParseCachingConfig(raw []byte) (*Config, error) {
	if raw == nil {
		maxSize := new(int64)
		*maxSize = defaultMaxSizeBytes
		return &Config{InterQueryBuiltinCache: InterQueryBuiltinCacheConfig{MaxSizeBytes: maxSize}}, nil
	}

	var config Config

	if err := util.Unmarshal(raw, &config); err == nil {
		if err = config.validateAndInjectDefaults(); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return &config, nil
}

func (c *Config) validateAndInjectDefaults() error {
	if c.InterQueryBuiltinCache.MaxSizeBytes == nil {
		maxSize := new(int64)
		*maxSize = defaultMaxSizeBytes
		c.InterQueryBuiltinCache.MaxSizeBytes = maxSize
	}
	return nil
}

// InterQueryCacheValue defines the interface for the data that the inter-query cache holds.
type InterQueryCacheValue interface {
	SizeInBytes() int64
}

// InterQueryCache defines the interface for the inter-query cache.
type InterQueryCache interface {
	Get(key ast.Value) (value InterQueryCacheValue, found bool)
	Insert(key ast.Value, value InterQueryCacheValue) int
	Delete(key ast.Value)
	UpdateConfig(config *Config)
}

// NewInterQueryCache returns a new inter-query cache.
func NewInterQueryCache(config *Config) InterQueryCache {
	return &cache{
		items:  map[string]InterQueryCacheValue{},
		usage:  0,
		config: config,
		l:      list.New(),
	}
}

type cache struct {
	items  map[string]InterQueryCacheValue
	usage  int64
	config *Config
	l      *list.List
	mtx    sync.Mutex
}

// Insert inserts a key k into the cache with value v.
func (c *cache) Insert(k ast.Value, v InterQueryCacheValue) (dropped int) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.unsafeInsert(k, v)
}

// Get returns the value in the cache for k.
func (c *cache) Get(k ast.Value) (InterQueryCacheValue, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.unsafeGet(k)
}

// Delete deletes the value in the cache for k.
func (c *cache) Delete(k ast.Value) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.unsafeDelete(k)
}

func (c *cache) UpdateConfig(config *Config) {
	if config == nil {
		return
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.config = config
}

func (c *cache) unsafeInsert(k ast.Value, v InterQueryCacheValue) (dropped int) {
	size := v.SizeInBytes()
	limit := c.maxSizeBytes()

	if limit > 0 {
		if size > limit {
			dropped++
			return dropped
		}

		for key := c.l.Front(); key != nil && (c.usage+size > limit); key = key.Next() {
			dropKey := key.Value.(ast.Value)
			c.unsafeDelete(dropKey)
			c.l.Remove(key)
			dropped++
		}
	}

	c.items[k.String()] = v
	c.l.PushBack(k)
	c.usage += size
	return dropped
}

func (c *cache) unsafeGet(k ast.Value) (InterQueryCacheValue, bool) {
	value, ok := c.items[k.String()]
	return value, ok
}

func (c *cache) unsafeDelete(k ast.Value) {
	value, ok := c.unsafeGet(k)
	if !ok {
		return
	}

	c.usage -= int64(value.SizeInBytes())
	delete(c.items, k.String())
}

func (c *cache) maxSizeBytes() int64 {
	if c.config == nil {
		return defaultMaxSizeBytes
	}
	return *c.config.InterQueryBuiltinCache.MaxSizeBytes
}
