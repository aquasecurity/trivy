package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		opts     cache.Options
		wantType any
		wantErr  string
	}{
		{
			name: "fs backend",
			opts: cache.Options{
				Backend:  "fs",
				CacheDir: "/tmp/cache",
			},
			wantType: cache.FSCache{},
		},
		{
			name: "redis backend",
			opts: cache.Options{
				Backend: "redis://localhost:6379",
			},
			wantType: cache.RedisCache{},
		},
		{
			name: "unknown backend",
			opts: cache.Options{
				Backend: "unknown",
			},
			wantErr: "unknown cache type",
		},
		{
			name: "invalid redis URL",
			opts: cache.Options{
				Backend: "redis://invalid-url:foo/bar",
			},
			wantErr: "failed to parse Redis URL",
		},
		{
			name: "incomplete TLS options",
			opts: cache.Options{
				Backend:     "redis://localhost:6379",
				RedisCACert: "testdata/ca-cert.pem",
				RedisTLS:    true,
			},
			wantErr: "you must provide Redis CA, cert and key file path when using TLS",
		},
		{
			name: "invalid TLS file paths",
			opts: cache.Options{
				Backend:     "redis://localhost:6379",
				RedisCACert: "testdata/non-existent-ca-cert.pem",
				RedisCert:   "testdata/non-existent-cert.pem",
				RedisKey:    "testdata/non-existent-key.pem",
				RedisTLS:    true,
			},
			wantErr: "failed to get TLS config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup, err := cache.New(tt.opts)
			defer cleanup()

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, c)
			assert.IsType(t, tt.wantType, c)
		})
	}
}

func TestNewType(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		wantType cache.Type
	}{
		{
			name:     "redis backend",
			backend:  "redis://localhost:6379",
			wantType: cache.TypeRedis,
		},
		{
			name:     "fs backend",
			backend:  "fs",
			wantType: cache.TypeFS,
		},
		{
			name:     "empty backend",
			backend:  "",
			wantType: cache.TypeFS,
		},
		{
			name:     "unknown backend",
			backend:  "unknown",
			wantType: cache.TypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.NewType(tt.backend)
			assert.Equal(t, tt.wantType, got)
		})
	}
}
