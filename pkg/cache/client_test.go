package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
)

func TestNewOptions(t *testing.T) {
	type args struct {
		backend     string
		redisCACert string
		redisCert   string
		redisKey    string
		redisTLS    bool
		ttl         time.Duration
	}
	tests := []struct {
		name      string
		args      args
		want      cache.Options
		assertion require.ErrorAssertionFunc
	}{
		{
			name:      "fs",
			args:      args{backend: "fs"},
			want:      cache.Options{Type: cache.TypeFS},
			assertion: require.NoError,
		},
		{
			name: "redis",
			args: args{backend: "redis://localhost:6379"},
			want: cache.Options{
				Type:  cache.TypeRedis,
				Redis: cache.RedisOptions{Backend: "redis://localhost:6379"},
			},
			assertion: require.NoError,
		},
		{
			name: "redis tls",
			args: args{
				backend:     "redis://localhost:6379",
				redisCACert: "ca-cert.pem",
				redisCert:   "cert.pem",
				redisKey:    "key.pem",
			},
			want: cache.Options{
				Type: cache.TypeRedis,
				Redis: cache.RedisOptions{
					Backend: "redis://localhost:6379",
					TLSOptions: cache.RedisTLSOptions{
						CACert: "ca-cert.pem",
						Cert:   "cert.pem",
						Key:    "key.pem",
					},
				},
			},
			assertion: require.NoError,
		},
		{
			name: "redis tls with public certificates",
			args: args{
				backend:  "redis://localhost:6379",
				redisTLS: true,
			},
			want: cache.Options{
				Type: cache.TypeRedis,
				Redis: cache.RedisOptions{
					Backend: "redis://localhost:6379",
					TLS:     true,
				},
			},
			assertion: require.NoError,
		},
		{
			name: "unknown backend",
			args: args{backend: "unknown"},
			assertion: func(t require.TestingT, err error, msgs ...any) {
				require.ErrorContains(t, err, "unknown cache backend")
			},
		},
		{
			name: "sad redis tls",
			args: args{
				backend:     "redis://localhost:6379",
				redisCACert: "ca-cert.pem",
			},
			assertion: func(t require.TestingT, err error, msgs ...any) {
				require.ErrorContains(t, err, "you must provide Redis CA, cert and key file path when using TLS")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cache.NewOptions(tt.args.backend, tt.args.redisCACert, tt.args.redisCert, tt.args.redisKey, tt.args.redisTLS, tt.args.ttl)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedisOptions_BackendMasked(t *testing.T) {
	tests := []struct {
		name   string
		fields cache.RedisOptions
		want   string
	}{
		{
			name:   "redis cache backend masked",
			fields: cache.RedisOptions{Backend: "redis://root:password@localhost:6379"},
			want:   "redis://****@localhost:6379",
		},
		{
			name:   "redis cache backend masked does nothing",
			fields: cache.RedisOptions{Backend: "redis://localhost:6379"},
			want:   "redis://localhost:6379",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.fields.BackendMasked())
		})
	}
}

func TestClient_Reset(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create test files and subdirectories
	subDir := filepath.Join(tempDir, "subdir")
	err := os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	testFile := filepath.Join(tempDir, "testfile.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Create a cache client
	client, err := cache.NewClient(tempDir, cache.Options{Type: cache.TypeFS})
	require.NoError(t, err)

	// Call Reset method
	err = client.Reset()
	require.NoError(t, err)

	// Verify that the subdirectory no longer exists
	require.NoDirExists(t, subDir, "Subdirectory should not exist after Reset")

	// Verify that the test file no longer exists
	require.NoFileExists(t, testFile, "Test file should not exist after Reset")

	// Verify that the cache directory no longer exists
	require.NoDirExists(t, tempDir, "Cache directory should not exist after Reset")
}

func TestClient_ClearArtifacts(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a client
	client, err := cache.NewClient(tempDir, cache.Options{Type: cache.TypeFS})
	require.NoError(t, err)

	require.FileExists(t, filepath.Join(tempDir, "fanal", "fanal.db"), "Database file should exist")

	// Call ClearArtifacts method
	err = client.ClearArtifacts()
	require.NoError(t, err)

	require.NoDirExists(t, filepath.Join(tempDir, "fanal"), "Artifact cache should not exist after ClearArtifacts")
}
