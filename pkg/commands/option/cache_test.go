package option_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy/pkg/commands/option"
)

func TestNewCacheOption(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want option.CacheOption
	}{
		{
			name: "happy path",
			args: []string{"--cache-backend", "redis://localhost:6379"},
			want: option.CacheOption{
				CacheBackend: "redis://localhost:6379",
			},
		},
		{
			name: "default",
			args: []string{},
			want: option.CacheOption{
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

			got := option.NewCacheOption(c)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestCacheOption_Init(t *testing.T) {
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
			c := &option.CacheOption{
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
