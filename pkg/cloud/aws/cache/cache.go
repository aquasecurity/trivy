package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/state"
)

type Cache struct {
	path      string
	accountID string
	region    string
	maxAge    time.Duration
}

const SchemaVersion = 2

type CacheData struct {
	SchemaVersion int                        `json:"schema_version"`
	State         *state.State               `json:"state"`
	Services      map[string]ServiceMetadata `json:"service_metadata"`
	Updated       time.Time                  `json:"updated"`
}

type ServiceMetadata struct {
	Name    string    `json:"name"`
	Updated time.Time `json:"updated"`
}

var ErrCacheNotFound = fmt.Errorf("cache record not found")
var ErrCacheIncompatible = fmt.Errorf("cache record used incomatible schema")
var ErrCacheExpired = fmt.Errorf("cache record expired")

func New(cacheDir string, maxCacheAge time.Duration, accountID string, region string) *Cache {
	return &Cache{
		path:      path.Join(cacheDir, "cloud", "aws", accountID, strings.ToLower(region), "data.json"),
		accountID: accountID,
		region:    region,
		maxAge:    maxCacheAge,
	}
}

func (c *Cache) load() (*CacheData, error) {

	m, err := os.Open(c.path)
	if err != nil {
		return nil, ErrCacheNotFound
	}
	defer func() { _ = m.Close() }()

	var data CacheData
	if err := json.NewDecoder(m).Decode(&data); err != nil {
		return nil, err
	}

	if data.SchemaVersion != SchemaVersion {
		return nil, ErrCacheIncompatible
	}

	if time.Since(data.Updated) > c.maxAge {
		return nil, ErrCacheExpired
	}

	return &data, nil
}

func (c *Cache) ListServices(required []string) (included []string, missing []string) {

	data, err := c.load()
	if err != nil {
		return nil, required
	}

	for _, service := range required {
		metadata, ok := data.Services[service]
		if !ok {
			missing = append(missing, service)
			continue
		}
		if time.Since(metadata.Updated) > c.maxAge {
			missing = append(missing, service)
			continue
		}
		included = append(included, service)
	}

	return included, missing
}

func (c *Cache) LoadState() (*state.State, error) {
	data, err := c.load()
	if err != nil {
		return nil, err
	}
	return data.State, nil
}

func (c *Cache) AddServices(state *state.State, includedServices []string) error {

	data := &CacheData{
		SchemaVersion: SchemaVersion,
		State:         state,
		Services:      map[string]ServiceMetadata{},
		Updated:       time.Now(),
	}

	if previous, err := c.load(); err == nil {
		data.Services = previous.Services
	}

	for _, service := range includedServices {
		data.Services[service] = ServiceMetadata{
			Name:    service,
			Updated: time.Now(),
		}
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil {
		return err
	}
	f, err := os.Create(c.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return json.NewEncoder(f).Encode(data)
}
