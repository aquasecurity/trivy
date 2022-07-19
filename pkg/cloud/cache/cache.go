package cache

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

const (
	metadataFilename = "metadata.json"
	cacheFilename    = "cache.json"
	dataDirName      = "data"
	cacheSubDir      = "cloud"
)

var ErrCacheNotFound = fmt.Errorf("cache record not found")

type Cache struct {
	path      string
	provider  string
	accountID string
	region    string
}

func New(basePath string, provider, accountID string, region string) *Cache {
	return &Cache{
		path:      path.Join(basePath, cacheSubDir, strings.ToLower(provider), accountID, strings.ToLower(region)),
		provider:  provider,
		accountID: accountID,
		region:    region,
	}
}

func (c *Cache) ListAvailableServices() []string {
	metadata, err := c.loadMetadata()
	if err != nil {
		return nil
	}
	return metadata.ServicesInScope
}

func (c *Cache) getServicePath(service string) string {
	service = strings.NewReplacer(" ", "_", ".", "_").Replace(service)
	return filepath.Join(c.path, dataDirName, service, cacheFilename)
}

func (c *Cache) getMetadataPath() string {
	return filepath.Join(c.path, metadataFilename)
}
