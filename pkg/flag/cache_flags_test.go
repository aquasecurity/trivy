package flag_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestCacheFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		ClearCache   bool
		CacheBackend string
		CacheTTL     time.Duration
		RedisTLS     bool
		RedisCACert  string
		RedisCert    string
		RedisKey     string
	}
	tests := []struct {
		name      string
		fields    fields
		want      flag.CacheOptions
		assertion require.ErrorAssertionFunc
	}{
		{
			name: "fs",
			fields: fields{
				CacheBackend: "fs",
			},
			want: flag.CacheOptions{
				CacheBackend: "fs",
			},
			assertion: require.NoError,
		},
		{
			name: "redis",
			fields: fields{
				CacheBackend: "redis://localhost:6379",
			},
			want: flag.CacheOptions{
				CacheBackend: "redis://localhost:6379",
			},
			assertion: require.NoError,
		},
		{
			name: "redis tls",
			fields: fields{
				CacheBackend: "redis://localhost:6379",
				RedisCACert:  "ca-cert.pem",
				RedisCert:    "cert.pem",
				RedisKey:     "key.pem",
			},
			want: flag.CacheOptions{
				CacheBackend: "redis://localhost:6379",
				RedisOptions: flag.RedisOptions{
					RedisCACert: "ca-cert.pem",
					RedisCert:   "cert.pem",
					RedisKey:    "key.pem",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "redis tls with public certificates",
			fields: fields{
				CacheBackend: "redis://localhost:6379",
				RedisTLS:     true,
			},
			want: flag.CacheOptions{
				CacheBackend: "redis://localhost:6379",
				RedisTLS:     true,
			},
			assertion: require.NoError,
		},
		{
			name: "unknown backend",
			fields: fields{
				CacheBackend: "unknown",
			},
			assertion: func(t require.TestingT, err error, msgs ...interface{}) {
				require.ErrorContains(t, err, "unsupported cache backend")
			},
		},
		{
			name: "sad redis tls",
			fields: fields{
				CacheBackend: "redis://localhost:6379",
				RedisCACert:  "ca-cert.pem",
			},
			assertion: func(t require.TestingT, err error, msgs ...interface{}) {
				require.ErrorContains(t, err, "you must provide Redis CA")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Set(flag.ClearCacheFlag.ConfigName, tt.fields.ClearCache)
			viper.Set(flag.CacheBackendFlag.ConfigName, tt.fields.CacheBackend)
			viper.Set(flag.CacheTTLFlag.ConfigName, tt.fields.CacheTTL)
			viper.Set(flag.RedisTLSFlag.ConfigName, tt.fields.RedisTLS)
			viper.Set(flag.RedisCACertFlag.ConfigName, tt.fields.RedisCACert)
			viper.Set(flag.RedisCertFlag.ConfigName, tt.fields.RedisCert)
			viper.Set(flag.RedisKeyFlag.ConfigName, tt.fields.RedisKey)

			f := &flag.CacheFlagGroup{
				ClearCache:   &flag.ClearCacheFlag,
				CacheBackend: &flag.CacheBackendFlag,
				CacheTTL:     &flag.CacheTTLFlag,
				RedisTLS:     &flag.RedisTLSFlag,
				RedisCACert:  &flag.RedisCACertFlag,
				RedisCert:    &flag.RedisCertFlag,
				RedisKey:     &flag.RedisKeyFlag,
			}

			got, err := f.ToOptions()
			tt.assertion(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")
		})
	}
}

func TestCacheOptions_CacheBackendMasked(t *testing.T) {
	type fields struct {
		backend string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "redis cache backend masked",
			fields: fields{
				backend: "redis://root:password@localhost:6379",
			},
			want: "redis://****@localhost:6379",
		},
		{
			name: "redis cache backend masked does nothing",
			fields: fields{
				backend: "redis://localhost:6379",
			},
			want: "redis://localhost:6379",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &flag.CacheOptions{
				CacheBackend: tt.fields.backend,
			}

			assert.Equal(t, tt.want, c.CacheBackendMasked())
		})
	}
}
