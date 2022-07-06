package flag_test

import (
	"bytes"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCacheOption(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want flag.CacheOptions
	}{
		{
			name: "happy path",
			args: []string{"--cache-backend", "redis://localhost:6379"},
			want: flag.CacheOptions{
				CacheBackend: "redis://localhost:6379",
			},
		},
		{
			name: "default",
			args: []string{},
			want: flag.CacheOptions{
				CacheBackend: "fs",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheFlags := flag.NewCacheFlags()
			cmd := commands.NewApp("dev")
			cmd.SetOut(&bytes.Buffer{})

			cacheFlags.AddFlags(cmd)
			cmd.SetArgs(tt.args)
			
			err := cmd.Execute()
			assert.NoError(t, err)

			got, err := cacheFlags.ToOptions()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

/*
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
			c := &flag.CacheOptions{
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

*/

func TestCacheOption_CacheBackendMasked(t *testing.T) {
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
