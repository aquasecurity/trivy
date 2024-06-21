package cache_test

import (
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
