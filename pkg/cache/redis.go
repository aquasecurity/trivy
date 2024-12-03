package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ Cache = (*RedisCache)(nil)

const redisPrefix = "fanal"

type RedisOptions struct {
	Backend    string
	TLS        bool
	TLSOptions RedisTLSOptions
}

func NewRedisOptions(backend, caCert, cert, key string, enableTLS bool) (RedisOptions, error) {
	tlsOpts, err := NewRedisTLSOptions(caCert, cert, key)
	if err != nil {
		return RedisOptions{}, xerrors.Errorf("redis TLS option error: %w", err)
	}

	return RedisOptions{
		Backend:    backend,
		TLS:        enableTLS,
		TLSOptions: tlsOpts,
	}, nil
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

type RedisCache struct {
	client     *redis.Client
	expiration time.Duration
}

func NewRedisCache(backend, caCertPath, certPath, keyPath string, enableTLS bool, ttl time.Duration) (RedisCache, error) {
	opts, err := NewRedisOptions(backend, caCertPath, certPath, keyPath, enableTLS)
	if err != nil {
		return RedisCache{}, xerrors.Errorf("failed to create Redis options: %w", err)
	}

	log.Info("Redis scan cache", log.String("url", opts.BackendMasked()))
	options, err := redis.ParseURL(opts.Backend)
	if err != nil {
		return RedisCache{}, xerrors.Errorf("failed to parse Redis URL: %w", err)
	}

	if tlsOpts := opts.TLSOptions; !lo.IsEmpty(tlsOpts) {
		caCert, cert, err := GetTLSConfig(tlsOpts.CACert, tlsOpts.Cert, tlsOpts.Key)
		if err != nil {
			return RedisCache{}, xerrors.Errorf("failed to get TLS config: %w", err)
		}

		options.TLSConfig = &tls.Config{
			RootCAs:      caCert,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else if opts.TLS {
		options.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	return RedisCache{
		client:     redis.NewClient(options),
		expiration: ttl,
	}, nil
}

func (c RedisCache) PutArtifact(artifactID string, artifactConfig types.ArtifactInfo) error {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, artifactID)
	b, err := json.Marshal(artifactConfig)
	if err != nil {
		return xerrors.Errorf("failed to marshal artifact JSON: %w", err)
	}
	if err := c.client.Set(context.TODO(), key, string(b), c.expiration).Err(); err != nil {
		return xerrors.Errorf("unable to store artifact information in Redis cache (%s): %w", artifactID, err)
	}
	return nil
}

func (c RedisCache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	b, err := json.Marshal(blobInfo)
	if err != nil {
		return xerrors.Errorf("failed to marshal blob JSON: %w", err)
	}
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, blobBucket, blobID)
	if err := c.client.Set(context.TODO(), key, string(b), c.expiration).Err(); err != nil {
		return xerrors.Errorf("unable to store blob information in Redis cache (%s): %w", blobID, err)
	}
	return nil
}
func (c RedisCache) DeleteBlobs(blobIDs []string) error {
	var errs error
	for _, blobID := range blobIDs {
		key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, blobID)
		if err := c.client.Del(context.TODO(), key).Err(); err != nil {
			errs = multierror.Append(errs, xerrors.Errorf("unable to delete blob %s: %w", blobID, err))
		}
	}
	return errs
}

func (c RedisCache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, artifactID)
	val, err := c.client.Get(context.TODO(), key).Bytes()
	if err == redis.Nil {
		return types.ArtifactInfo{}, xerrors.Errorf("artifact (%s) is missing in Redis cache", artifactID)
	} else if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("failed to get artifact from the Redis cache: %w", err)
	}

	var info types.ArtifactInfo
	err = json.Unmarshal(val, &info)
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("failed to unmarshal artifact (%s) from Redis value: %w", artifactID, err)
	}
	return info, nil
}

func (c RedisCache) GetBlob(blobID string) (types.BlobInfo, error) {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, blobBucket, blobID)
	val, err := c.client.Get(context.TODO(), key).Bytes()
	if err == redis.Nil {
		return types.BlobInfo{}, xerrors.Errorf("blob (%s) is missing in Redis cache", blobID)
	} else if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to get blob from the Redis cache: %w", err)
	}

	var blobInfo types.BlobInfo
	if err = json.Unmarshal(val, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to unmarshal blob (%s) from Redis value: %w", blobID, err)
	}
	return blobInfo, nil
}

func (c RedisCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string
	for _, blobID := range blobIDs {
		blobInfo, err := c.GetBlob(blobID)
		if err != nil {
			// error means cache missed blob info
			missingBlobIDs = append(missingBlobIDs, blobID)
			continue
		}
		if blobInfo.SchemaVersion != types.BlobJSONSchemaVersion {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}
	// get artifact info
	artifactInfo, err := c.GetArtifact(artifactID)
	// error means cache missed artifact info
	if err != nil {
		return true, missingBlobIDs, nil
	}
	if artifactInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingArtifact = true
	}
	return missingArtifact, missingBlobIDs, nil
}

func (c RedisCache) Close() error {
	return c.client.Close()
}

func (c RedisCache) Clear() error {
	ctx := context.Background()

	for {
		keys, cursor, err := c.client.Scan(ctx, 0, redisPrefix+"::*", 100).Result()
		if err != nil {
			return xerrors.Errorf("failed to perform prefix scanning: %w", err)
		}
		if err = c.client.Unlink(ctx, keys...).Err(); err != nil {
			return xerrors.Errorf("failed to unlink redis keys: %w", err)
		}
		if cursor == 0 { // We cleared all keys
			break
		}
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
