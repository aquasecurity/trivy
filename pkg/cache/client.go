package cache

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	TypeFS    Type = "fs"
	TypeRedis Type = "redis"
)

type Client struct {
	dir string
	Cache
}

type Type string

type Options struct {
	Type  Type
	TTL   time.Duration
	Redis RedisOptions
}

func NewOptions(backend, redisCACert, redisCert, redisKey string, redisTLS bool, ttl time.Duration) (Options, error) {
	t, err := NewType(backend)
	if err != nil {
		return Options{}, xerrors.Errorf("cache type error: %w", err)
	}

	var redisOpts RedisOptions
	if t == TypeRedis {
		redisTLSOpts, err := NewRedisTLSOptions(redisCACert, redisCert, redisKey)
		if err != nil {
			return Options{}, xerrors.Errorf("redis TLS option error: %w", err)
		}
		redisOpts = RedisOptions{
			Backend:    backend,
			TLS:        redisTLS,
			TLSOptions: redisTLSOpts,
		}
	} else if ttl != 0 {
		log.Warn("'--cache-ttl' is only available with Redis cache backend")
	}

	return Options{
		Type:  t,
		TTL:   ttl,
		Redis: redisOpts,
	}, nil
}

type RedisOptions struct {
	Backend    string
	TLS        bool
	TLSOptions RedisTLSOptions
}

// BackendMasked returns the redis connection string masking credentials
func (o *RedisOptions) BackendMasked() string {
	endIndex := strings.Index(o.Backend, "@")
	if endIndex == -1 {
		return o.Backend
	}

	startIndex := strings.Index(o.Backend, "//")

	return fmt.Sprintf("%s****%s", o.Backend[:startIndex+2], o.Backend[endIndex:])
}

// RedisTLSOptions holds the options for redis cache
type RedisTLSOptions struct {
	CACert string
	Cert   string
	Key    string
}

func NewRedisTLSOptions(caCert, cert, key string) (RedisTLSOptions, error) {
	opts := RedisTLSOptions{
		CACert: caCert,
		Cert:   cert,
		Key:    key,
	}

	// If one of redis option not nil, make sure CA, cert, and key provided
	if !lo.IsEmpty(opts) {
		if opts.CACert == "" || opts.Cert == "" || opts.Key == "" {
			return RedisTLSOptions{}, xerrors.Errorf("you must provide Redis CA, cert and key file path when using TLS")
		}
	}
	return opts, nil
}

func NewType(backend string) (Type, error) {
	// "redis://" or "fs" are allowed for now
	// An empty value is also allowed for testability
	switch {
	case strings.HasPrefix(backend, "redis://"):
		return TypeRedis, nil
	case backend == "fs", backend == "":
		return TypeFS, nil
	default:
		return "", xerrors.Errorf("unknown cache backend: %s", backend)
	}
}

// NewClient returns a new cache client
func NewClient(dir string, opts Options) (*Client, error) {
	client := &Client{dir: dir}
	if opts.Type == TypeRedis {
		log.Info("Redis cache", log.String("url", opts.Redis.BackendMasked()))
		options, err := redis.ParseURL(opts.Redis.Backend)
		if err != nil {
			return nil, err
		}

		if tlsOpts := opts.Redis.TLSOptions; !lo.IsEmpty(tlsOpts) {
			caCert, cert, err := GetTLSConfig(tlsOpts.CACert, tlsOpts.Cert, tlsOpts.Key)
			if err != nil {
				return nil, err
			}

			options.TLSConfig = &tls.Config{
				RootCAs:      caCert,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else if opts.Redis.TLS {
			options.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		client.Cache = NewRedisCache(options, opts.TTL)
		return client, nil
	}

	// standalone mode
	var err error
	client.Cache, err = NewFSCache(dir)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize fs cache: %w", err)
	}
	return client, nil
}

// Reset resets the cache
func (c *Client) Reset() error {
	log.Info("Removing all caches...")
	if err := c.Clear(); err != nil {
		return xerrors.Errorf("failed to remove the cache: %w", err)
	}
	if err := os.RemoveAll(c.dir); err != nil {
		return xerrors.Errorf("failed to remove the directory (%s) : %w", c.dir, err)
	}
	return nil
}

// ClearArtifacts clears the artifact cache
func (c *Client) ClearArtifacts() error {
	log.Info("Removing artifact caches...")
	if err := c.Clear(); err != nil {
		return xerrors.Errorf("failed to remove the cache: %w", err)
	}
	return nil
}

// GetTLSConfig gets tls config from CA, Cert and Key file
func GetTLSConfig(caCertPath, certPath, keyPath string) (*x509.CertPool, tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, cert, nil
}
