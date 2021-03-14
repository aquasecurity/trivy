package config_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands/config"
)

func TestNewCacheConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want config.CacheConfig
	}{
		{
			name: "happy path",
			args: []string{"--cache-backend", "redis://localhost:6379"},
			want: config.CacheConfig{
				CacheBackend: "redis://localhost:6379",
			},
		},
		{
			name: "default",
			args: []string{},
			want: config.CacheConfig{
				CacheBackend: "fs",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.String("cache-backend", "fs", "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			got := config.NewCacheConfig(c)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestCacheConfig_Init(t *testing.T) {
	type fields struct {
		backend string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr string
	}{
		{
			name: "fs",
			fields: fields{
				backend: "fs",
			},
		},
		{
			name: "redis",
			fields: fields{
				backend: "redis://localhost:6379",
			},
		},
		{
			name: "sad path",
			fields: fields{
				backend: "unknown://",
			},
			wantErr: "unsupported cache backend: unknown://",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.CacheConfig{
				CacheBackend: tt.fields.backend,
			}

			err := c.Init()
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
