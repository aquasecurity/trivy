package option

import (
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

// CacheOption holds the options for cache
type CacheOption struct {
	CacheBackend string
}

// NewCacheOption returns an instance of CacheOption
func NewCacheOption(c *cli.Context) CacheOption {
	return CacheOption{
		CacheBackend: c.String("cache-backend"),
	}
}

// Init initialize the CacheOption
func (c *CacheOption) Init() error {
	// "redis://" or "fs" are allowed for now
	// An empty value is also allowed for testability
	if !strings.HasPrefix(c.CacheBackend, "redis://") &&
		c.CacheBackend != "fs" && c.CacheBackend != "" {
		return xerrors.Errorf("unsupported cache backend: %s", c.CacheBackend)
	}
	return nil
}
