package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key      string
		versions map[string]int
		patterns []string
		policy   []string
		data     []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with disabled analyzer",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 0,
					"redhat": 2,
				},
			},
			want: "sha256:dff5eb1aa155d720a7949d2ca8abb48d91762bf8b39dd4bfc5c5db17d9d3ccc3",
		},
		{
			name: "with empty slice file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with single empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{""},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with single non empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test"},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with non empty followed by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test", ""},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with non empty preceded by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"", "test"},
			},
			want: "sha256:51685eab32590231b0c9b1114e556cb3247ead73bfd86ecf9a11632147eb7333",
		},
		{
			name: "with policy",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"testdata"},
			},
			want: "sha256:853fc0e8c43f7c764e2319498ad8e6e9a0ee4791ad5de2d223ce093cb9a8aef7",
		},
		{
			name: "with policy/non-existent dir",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				versions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"policydir"},
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := &config.ScannerOption{
				FilePatterns: tt.args.patterns,
				PolicyPaths:  tt.args.policy,
				DataPaths:    tt.args.data,
			}
			got, err := CalcKey(tt.args.key, tt.args.versions, opt)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
