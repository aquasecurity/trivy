package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key              string
		analyzerVersions map[string]int
		hookVersions     map[string]int
		patterns         []string
		policy           []string
		data             []string
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
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:dcdf828ab855918fc61688c8a9e27d011579601faef57122655d9e10128b2898",
		},
		{
			name: "with disabled analyzer",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 0,
					"redhat": 2,
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:796a061d4942fe2eb1a3559cf4a4cff2500eb2dc67d6cd4a1e5914250b6db994",
		},
		{
			name: "with empty slice file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{},
			},
			want: "sha256:0ecded9645d88f15c2372741abb3e52b4c4fc83ccad1df57a67e4b92b2da7200",
		},
		{
			name: "with single empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{""},
			},
			want: "sha256:0ecded9645d88f15c2372741abb3e52b4c4fc83ccad1df57a67e4b92b2da7200",
		},
		{
			name: "with single non empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test"},
			},
			want: "sha256:0ecded9645d88f15c2372741abb3e52b4c4fc83ccad1df57a67e4b92b2da7200",
		},
		{
			name: "with non empty followed by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"test", ""},
			},
			want: "sha256:0ecded9645d88f15c2372741abb3e52b4c4fc83ccad1df57a67e4b92b2da7200",
		},
		{
			name: "with non empty preceded by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				patterns: []string{"", "test"},
			},
			want: "sha256:0ecded9645d88f15c2372741abb3e52b4c4fc83ccad1df57a67e4b92b2da7200",
		},
		{
			name: "with policy",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"testdata"},
			},
			want: "sha256:dd247485b0c153e3a438c70b06b1e711b78b8a5c08da3f0a8c76efdf3a4d3194",
		},
		{
			name: "with policy/non-existent dir",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
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
			got, err := CalcKey(tt.args.key, tt.args.analyzerVersions, tt.args.hookVersions, opt)
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
