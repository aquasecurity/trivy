package flag

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"golang.org/x/xerrors"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

const (
	ClearCacheFlag   = "clear-cache"
	CacheBackendFlag = "cache-backend"
	CacheTTLFlag     = "cache-ttl"
	RedisCACertFlag  = "redis-ca"
	RedisCertFlag    = "redis-cert"
	RedisKeyFlag     = "redis-key"
)

// CacheFlags composes common printer flag structs used for commands requiring cache logic.
type CacheFlags struct {
	ClearCache   *bool
	CacheBackend *string
	CacheTTL     *time.Duration

	RedisCACert *string
	RedisCert   *string
	RedisKey    *string
}

type CacheOptions struct {
	ClearCache   bool
	CacheBackend string
	CacheTTL     time.Duration
	RedisOptions
}

// RedisOptions holds the options for redis cache
type RedisOptions struct {
	RedisCACert string
	RedisCert   string
	RedisKey    string
}

// NewCacheFlags returns a default CacheFlags
func NewCacheFlags() *CacheFlags {
	return &CacheFlags{
		ClearCache:   lo.ToPtr(false),
		CacheBackend: lo.ToPtr("fs"),
		CacheTTL:     lo.ToPtr(time.Duration(0)),
		RedisCACert:  lo.ToPtr(""),
		RedisCert:    lo.ToPtr(""),
		RedisKey:     lo.ToPtr(""),
	}
}

func (f *CacheFlags) AddFlags(cmd *cobra.Command) {
	if f.ClearCache != nil {
		cmd.Flags().Bool(ClearCacheFlag, *f.ClearCache, "clear image caches without scanning")
	}
	if f.CacheBackend != nil {
		cmd.Flags().String(CacheBackendFlag, *f.CacheBackend, "cache backend (e.g. redis://localhost:6379)")
	}
	if f.CacheTTL != nil {
		cmd.Flags().Duration(CacheTTLFlag, *f.CacheTTL, "cache TTL when using redis as cache backend")
	}
	if f.RedisCACert != nil {
		cmd.Flags().String(RedisCACertFlag, *f.RedisCACert, "redis ca file location, if using redis as cache backend")
	}
	if f.RedisCert != nil {
		cmd.Flags().String(RedisCertFlag, *f.RedisCert, "redis certificate file location, if using redis as cache backend")
	}
	if f.RedisKey != nil {
		cmd.Flags().String(RedisKeyFlag, *f.RedisKey, "redis key file location, if using redis as cache backend")
	}
}

func (f *CacheFlags) ToOptions() (CacheOptions, error) {
	cacheBackend := viper.GetString(CacheBackendFlag)
	redisOptions := RedisOptions{
		RedisCACert: viper.GetString(RedisCACertFlag),
		RedisCert:   viper.GetString(RedisCertFlag),
		RedisKey:    viper.GetString(RedisKeyFlag),
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
		ClearCache:   viper.GetBool(ClearCacheFlag),
		CacheBackend: cacheBackend,
		CacheTTL:     viper.GetDuration(CacheTTLFlag),
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
