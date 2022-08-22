package cache

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
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
	maxAge    time.Duration
}

func New(basePath string, maxAge time.Duration, provider string, accountID string, region string) *Cache {
	return &Cache{
		path:      path.Join(basePath, cacheSubDir, strings.ToLower(provider), accountID, strings.ToLower(region)),
		provider:  provider,
		accountID: accountID,
		region:    region,
		maxAge:    maxAge,
	}
}

func (c *Cache) ListAvailableServices(includeExpired bool) []string {
	metadata, err := c.loadMetadata()
	if err != nil {
		return nil
	}
	r, err := c.LoadReport(metadata.ServicesInScope...)
	if err != nil {
		return nil
	}
	var available []string
	for _, service := range metadata.ServicesInScope {
		if entry, ok := r.Results[service]; ok {
			if includeExpired || entry.CreationTime.Add(c.maxAge).After(time.Now()) {
				available = append(available, service)
			}
		}
	}
	return available
}

func (c *Cache) getServicePath(service string) string {
	service = strings.NewReplacer(" ", "_", ".", "_").Replace(service)
	return filepath.Join(c.path, dataDirName, service, cacheFilename)
}

func (c *Cache) getMetadataPath() string {
	return filepath.Join(c.path, metadataFilename)
}
