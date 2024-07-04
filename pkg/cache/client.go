package cache

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	TypeUnknown Type = "unknown"
	TypeFS      Type = "fs"
	TypeRedis   Type = "redis"
	TypeMemory  Type = "memory"
	TypeS3      Type = "s3"
)

type Type string

type Options struct {
	Backend     string
	CacheDir    string
	RedisCACert string
	RedisCert   string
	RedisKey    string
	RedisTLS    bool
	TTL         time.Duration
}

func NewType(backend string) Type {
	// "redis://" or "fs" are allowed for now
	// An empty value is also allowed for testability
	switch {
	case strings.HasPrefix(backend, "redis://"):
		return TypeRedis
	case backend == "fs", backend == "":
		return TypeFS
	case backend == "memory":
		return TypeMemory
	case strings.HasPrefix(backend, "s3://"):
		return TypeS3
	default:
		return TypeUnknown
	}
}

// New returns a new cache client
func New(opts Options) (Cache, func(), error) {
	cleanup := func() {} // To avoid panic

	var cache Cache
	t := NewType(opts.Backend)
	log.Debug("Initializing scan cache...", log.String("type", string(t)))
	switch t {
	case TypeRedis:
		redisCache, err := NewRedisCache(opts.Backend, opts.RedisCACert, opts.RedisCert, opts.RedisKey, opts.RedisTLS, opts.TTL)
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to initialize redis cache: %w", err)
		}
		cache = redisCache
	case TypeFS:
		// standalone mode
		fsCache, err := NewFSCache(opts.CacheDir)
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to initialize fs cache: %w", err)
		}
		cache = fsCache
	case TypeMemory:
		cache = NewMemoryCache()
	case TypeS3:
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to load AWS SDK config: %w", err)
		}
		client := s3.NewFromConfig(cfg)
		bucket := strings.TrimPrefix(opts.Backend, "s3://")
		bucket, prefix, _ := strings.Cut(bucket, "/")
		cache = NewS3Cache(client, bucket, prefix)
	default:
		return nil, cleanup, xerrors.Errorf("unknown cache type: %s", t)
	}
	return cache, func() { _ = cache.Close() }, nil
}
