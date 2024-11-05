package flag

import (
	"time"
)

// e.g. config yaml:
//
//	cache:
//	  clear: true
//	  backend: "redis://localhost:6379"
//	redis:
//	  ca: ca-cert.pem
//	  cert: cert.pem
//	  key: key.pem
var (
	// Deprecated
	ClearCacheFlag = Flag[bool]{
		Name:       "clear-cache",
		ConfigName: "cache.clear",
		Usage:      "clear image caches without scanning",
		Removed:    `Use "trivy clean --scan-cache" instead`,
	}
	CacheBackendFlag = Flag[string]{
		Name:       "cache-backend",
		ConfigName: "cache.backend",
		Default:    "fs",
		Usage:      "[EXPERIMENTAL] cache backend (e.g. redis://localhost:6379)",
	}
	CacheTTLFlag = Flag[time.Duration]{
		Name:       "cache-ttl",
		ConfigName: "cache.ttl",
		Usage:      "cache TTL when using redis as cache backend",
	}
	RedisTLSFlag = Flag[bool]{
		Name:       "redis-tls",
		ConfigName: "cache.redis.tls",
		Usage:      "enable redis TLS with public certificates, if using redis as cache backend",
	}
	RedisCACertFlag = Flag[string]{
		Name:       "redis-ca",
		ConfigName: "cache.redis.ca",
		Usage:      "redis ca file location, if using redis as cache backend",
	}
	RedisCertFlag = Flag[string]{
		Name:       "redis-cert",
		ConfigName: "cache.redis.cert",
		Usage:      "redis certificate file location, if using redis as cache backend",
	}
	RedisKeyFlag = Flag[string]{
		Name:       "redis-key",
		ConfigName: "cache.redis.key",
		Usage:      "redis key file location, if using redis as cache backend",
	}
)

// CacheFlagGroup composes common printer flag structs used for commands requiring cache logic.
type CacheFlagGroup struct {
	ClearCache   *Flag[bool]
	CacheBackend *Flag[string]
	CacheTTL     *Flag[time.Duration]

	RedisTLS    *Flag[bool]
	RedisCACert *Flag[string]
	RedisCert   *Flag[string]
	RedisKey    *Flag[string]
}

type CacheOptions struct {
	ClearCache bool

	CacheBackend string
	CacheTTL     time.Duration
	RedisTLS     bool
	RedisCACert  string
	RedisCert    string
	RedisKey     string
}

// NewCacheFlagGroup returns a default CacheFlagGroup
func NewCacheFlagGroup() *CacheFlagGroup {
	return &CacheFlagGroup{
		ClearCache:   ClearCacheFlag.Clone(),
		CacheBackend: CacheBackendFlag.Clone(),
		CacheTTL:     CacheTTLFlag.Clone(),
		RedisTLS:     RedisTLSFlag.Clone(),
		RedisCACert:  RedisCACertFlag.Clone(),
		RedisCert:    RedisCertFlag.Clone(),
		RedisKey:     RedisKeyFlag.Clone(),
	}
}

func (fg *CacheFlagGroup) Name() string {
	return "Cache"
}

func (fg *CacheFlagGroup) Flags() []Flagger {
	return []Flagger{
		fg.ClearCache,
		fg.CacheBackend,
		fg.CacheTTL,
		fg.RedisTLS,
		fg.RedisCACert,
		fg.RedisCert,
		fg.RedisKey,
	}
}

func (fg *CacheFlagGroup) ToOptions() (CacheOptions, error) {
	if err := parseFlags(fg); err != nil {
		return CacheOptions{}, err
	}

	return CacheOptions{
		CacheBackend: fg.CacheBackend.Value(),
		CacheTTL:     fg.CacheTTL.Value(),
		RedisTLS:     fg.RedisTLS.Value(),
		RedisCACert:  fg.RedisCACert.Value(),
		RedisCert:    fg.RedisCert.Value(),
		RedisKey:     fg.RedisKey.Value(),
	}, nil
}
