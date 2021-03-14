package config

import (
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

// CacheConfig holds the config for cache
type CacheConfig struct {
	CacheBackend string
}

// NewCacheConfig returns an instance of CacheConfig
func NewCacheConfig(c *cli.Context) CacheConfig {
	return CacheConfig{
		CacheBackend: c.String("cache-backend"),
	}
}

// Init initialize the CacheConfig
func (c *CacheConfig) Init() error {
	// "redis://" or "fs" are allowed for now
	// An empty value is also allowed for testability
	if !strings.HasPrefix(c.CacheBackend, "redis://") &&
		c.CacheBackend != "fs" && c.CacheBackend != "" {
		return xerrors.Errorf("unsupported cache backend: %s", c.CacheBackend)
	}
	return nil
}
