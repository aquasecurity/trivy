package pom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"golang.org/x/xerrors"
)

// Maximum number of I/O timeouts Trivy will tolerate before skipping future requests to the domain
// Without this, some scans can take a very long time because every request to a domain times out, one by one
const MaxDomainTimeouts = 2

// Cache settings

const (
	mavenHttpCacheDir = "maven_http_cache"
	domainsFileName   = "domains.json"
)

// mavenHttpCacheEntry represents a cached HTTP response
type mavenHttpCacheEntry struct {
	Data       []byte    `json:"data"`
	CachedAt   time.Time `json:"cached_at"`
	StatusCode int       `json:"status_code"`
	// The URL this cached entry was resolved from, for record-keeping
	Url string `json:"url"`
}

// mavenHttpCache handles filesystem caching of HTTP responses
type mavenHttpCache struct {
	cacheDir string
	// cache entry TTL
	ttl             time.Duration
	domainsFilePath string
	domainBlocklist []blocklistEntry
	domainTimeouts  map[string]int
	logger          *log.Logger
	initialized     bool
}

func (c *mavenHttpCache) logDomainBlocklist() {
	names := make([]string, len(c.domainBlocklist))
	for i, entry := range c.domainBlocklist {
		names[i] = entry.Name
	}

	c.logger.Debug(
		"Maven cache domainBlocklist ",
		log.String("domainBlocklist", strings.Join(names, ", ")),
	)
}

func newMavenHttpCache(logger *log.Logger, ttlMinutes int) *mavenHttpCache {
	var cacheDir string = filepath.Join(cache.DefaultDir(), mavenHttpCacheDir)
	var domainsFilePath string = filepath.Join(cacheDir, domainsFileName)
	var ttl time.Duration = time.Duration(ttlMinutes) * time.Minute

	logger.Debug(
		"New Maven cache ",
		log.String("cacheDir", cacheDir),
		log.Duration("ttl", ttl),
		log.String("domainsFilePath", domainsFilePath),
	)

	var cache = &mavenHttpCache{
		cacheDir:        cacheDir,
		ttl:             ttl,
		domainsFilePath: domainsFilePath,
		domainBlocklist: []blocklistEntry{},
		domainTimeouts:  make(map[string]int),
		logger:          logger,
		initialized:     false,
	}

	cache.domainBlocklist, _ = cache.readDomainBlocklist()
	cache.logDomainBlocklist()

	// Ensure cache directory exists
	if err := os.MkdirAll(cache.cacheDir, 0755); err != nil {
		logger.Warn(
			"Error creating Maven cache directory ",
			log.Err(err),
		)
		return cache
	}

	cache.initialized = true

	return cache
}

// cacheKey generates a cache key for the given URL
func (c *mavenHttpCache) cacheKey(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:])
}

// get retrieves a cached HTTP response if it exists and hasn't expired
func (c *mavenHttpCache) get(path string) (*mavenHttpCacheEntry, error) {
	if !c.initialized {
		return nil, xerrors.Errorf("Maven cache is not initialized")
	}

	key := c.cacheKey(path)
	cacheFile := filepath.Join(c.cacheDir, key+".json")

	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil, nil // Cache miss
	}

	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, xerrors.Errorf("failed to read cache file: %w", err)
	}

	var entry mavenHttpCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// If we can't parse the cache file, remove it and return cache miss
		_ = os.Remove(cacheFile)
		return nil, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.CachedAt.Add(c.ttl)) {
		// Lazy purge expired entry
		_ = os.Remove(cacheFile)
		return nil, nil
	}

	return &entry, nil
}

// set stores an HTTP response in the cache
func (c *mavenHttpCache) set(url string, path string, data []byte, statusCode int) error {
	if !c.initialized {
		return xerrors.Errorf("Maven cache is not initialized")
	}

	key := c.cacheKey(path)
	cacheFile := filepath.Join(c.cacheDir, key+".json")

	entry := mavenHttpCacheEntry{
		Data:       data,
		CachedAt:   time.Now(),
		StatusCode: statusCode,
		Url:        url,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return xerrors.Errorf("failed to marshal cache entry: %w", err)
	}

	if err := os.WriteFile(cacheFile, jsonData, 0644); err != nil {
		return xerrors.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

type blocklistEntry struct {
	Name     string    `json:"name"`
	CachedAt time.Time `json:"cached_at"`
}

type domainsJson struct {
	Blocklist []blocklistEntry `json:"blocklist"`
}

func isMavenReleaseDomain(name string) bool {
	for _, repoUrl := range mavenReleaseRepos {
		u, err := url.Parse(repoUrl)

		if err != nil {
			continue // skip malformed URLs
		}

		if name == u.Host {
			return true
		}
	}

	return false
}

// Blocklist a domain for the cache TTL period. Repos in mavenReleaseRepos cannot be blocklisted
func (c *mavenHttpCache) blocklistDomain(name string) error {
	c.logger.Debug("blocklistDomain[" + name + "] blocklisting domain...")
	var newBlocklistEntry blocklistEntry = blocklistEntry{
		Name:     name,
		CachedAt: time.Now(),
	}

	if !c.initialized {
		c.logger.Debug("blocklistDomain[" + name + "] Maven cache is not initialized. Exiting")
		return xerrors.Errorf("Maven cache is not initialized")
	}

	currentDomainBlocklist, err := c.readDomainBlocklist()

	c.logger.Debug("blocklistDomain[" + name + "] Read domain blocklist")

	if err != nil {
		c.logger.Debug("blocklistDomain["+name+"] Failed to read domain blocklist", log.Err(err))
		return xerrors.Errorf("Failed to read domain blocklist, skipping blocklist: %w", err)
	}

	// Skip blocklisting configured Maven release domains to avoid DoS
	if isMavenReleaseDomain(name) {
		c.logger.Debug("blocklistDomain[" + name + "] Domain is Maven release domain, skipping blocklist")
		return nil
	}

	// Skip adding the domain to the blocklist if it's already present
	for _, d := range currentDomainBlocklist {
		if d.Name == name {
			c.logger.Debug("blocklistDomain[" + name + "] Domain is already in blocklist, skipping blocklist")
			return nil
		}
	}

	// Add the new domain to blocklist
	currentDomainBlocklist = append(currentDomainBlocklist, newBlocklistEntry)
	// Update the in-memory blocklist
	c.domainBlocklist = currentDomainBlocklist

	// Encode and write back
	jsonData, err := json.Marshal(domainsJson{
		Blocklist: currentDomainBlocklist,
	})

	if err != nil {
		c.logger.Debug("blocklistDomain["+name+"] failed to marshal domains json", log.Err(err))
		return xerrors.Errorf("failed to marshal domains json: %w", err)
	}

	if err := os.WriteFile(c.domainsFilePath, jsonData, 0644); err != nil {
		c.logger.Debug("blocklistDomain["+name+"] failed to write domains json file", log.Err(err))
		return xerrors.Errorf("failed to write domains json file: %w", err)
	}

	// Success
	return nil
}

// readDomainBlocklist reads and returns the current domain blocklist, filtering out expired entries
func (c *mavenHttpCache) readDomainBlocklist() ([]blocklistEntry, error) {
	if _, err := os.Stat(c.domainsFilePath); os.IsNotExist(err) {
		c.logger.Debug("Domains file does not exist, default to empty blocklist")
		return []blocklistEntry{}, nil
	}

	var currentDomainBlocklist []blocklistEntry

	b, err := os.ReadFile(c.domainsFilePath)
	if err != nil {
		return []blocklistEntry{}, xerrors.Errorf("Failed to read domains file: %w", err)
	}

	if err := json.Unmarshal(b, &currentDomainBlocklist); err != nil {
		return []blocklistEntry{}, xerrors.Errorf("Failed to unmarshal domains file: %w", err)
	}

	now := time.Now()

	var unexpiredBlocklist []blocklistEntry
	for _, d := range currentDomainBlocklist {
		if now.Before(d.CachedAt.Add(c.ttl)) {
			unexpiredBlocklist = append(unexpiredBlocklist, d)
		}
	}

	return unexpiredBlocklist, nil
}

// Determine whether a domain is blocklisted by consulting the in-memory blocklist (synced with filesystem blocklist at process startup)
func (c *mavenHttpCache) isDomainBlocklisted(name string) bool {
	if !c.initialized {
		return false
	}

	now := time.Now()

	for _, d := range c.domainBlocklist {
		if now.Before(d.CachedAt.Add(c.ttl)) {
			if d.Name == name {
				return true
			}
		}
	}

	return false
}
