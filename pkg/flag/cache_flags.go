package flag

import (
	"fmt"
	"strings"
	"time"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
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
	ClearCacheFlag = Flag[bool]{
		Name:       "clear-cache",
		ConfigName: "cache.clear",
		Usage:      "clear image caches without scanning",
	}
	CacheBackendFlag = Flag[string]{
		Name:       "cache-backend",
		ConfigName: "cache.backend",
		Default:    "fs",
		Usage:      "cache backend (e.g. redis://localhost:6379)",
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
	ClearCache   bool
	CacheBackend string
	CacheTTL     time.Duration
	RedisTLS     bool
	RedisOptions
}

// RedisOptions holds the options for redis cache
type RedisOptions struct {
	RedisCACert string
	RedisCert   string
	RedisKey    string
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

	cacheBackend := fg.CacheBackend.Value()
	redisOptions := RedisOptions{
		RedisCACert: fg.RedisCACert.Value(),
		RedisCert:   fg.RedisCert.Value(),
		RedisKey:    fg.RedisKey.Value(),
	}

	// "redis://" or "fs" are allowed for now
	// An empty value is also allowed for testability
	if !strings.HasPrefix(cacheBackend, "redis://") &&
		cacheBackend != "fs" && cacheBackend != "" {
		return CacheOptions{}, xerrors.Errorf("unsupported cache backend: %s", cacheBackend)
	}
	// if one of redis option not nil, make sure CA, cert, and key provided
	if !lo.IsEmpty(redisOptions) {
		if redisOptions.RedisCACert == "" || redisOptions.RedisCert == "" || redisOptions.RedisKey == "" {
			return CacheOptions{}, xerrors.Errorf("you must provide Redis CA, cert and key file path when using TLS")
		}
	}

	return CacheOptions{
		ClearCache:   fg.ClearCache.Value(),
		CacheBackend: cacheBackend,
		CacheTTL:     fg.CacheTTL.Value(),
		RedisTLS:     fg.RedisTLS.Value(),
		RedisOptions: redisOptions,
	}, nil
}

// CacheBackendMasked returns the redis connection string masking credentials
func (o *CacheOptions) CacheBackendMasked() string {
	endIndex := strings.Index(o.CacheBackend, "@")
	if endIndex == -1 {
		return o.CacheBackend
	}

	startIndex := strings.Index(o.CacheBackend, "//")

	return fmt.Sprintf("%s****%s", o.CacheBackend[:startIndex+2], o.CacheBackend[endIndex:])
}
