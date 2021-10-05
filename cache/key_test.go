package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key              string
		analyzerVersions map[string]int
		hookVersions     map[string]int
		skipFiles        []string
		skipDirs         []string
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
			want: "sha256:8060f9cc9ba29039785a7116ae874673ad7a6eab37170ee1375b4064a72343ae",
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
			want: "sha256:e6a28d20a3a901377dcb836959c8ac268ec573735a5ba9c29112a1f6c5b1edd2",
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
			want: "sha256:d69f13df33f4c159b4ea54c1967384782fcefb5e2a19af35f4cd6d2896e9285e",
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
			want: "sha256:d69f13df33f4c159b4ea54c1967384782fcefb5e2a19af35f4cd6d2896e9285e",
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
			want: "sha256:d69f13df33f4c159b4ea54c1967384782fcefb5e2a19af35f4cd6d2896e9285e",
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
			want: "sha256:d69f13df33f4c159b4ea54c1967384782fcefb5e2a19af35f4cd6d2896e9285e",
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
			want: "sha256:d69f13df33f4c159b4ea54c1967384782fcefb5e2a19af35f4cd6d2896e9285e",
		},
		{
			name: "with policy",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				policy: []string{"testdata/policy"},
			},
			want: "sha256:96e90ded238ad2ea8e1fd53a4202247aa65b69ad5e2f9f60d883104865ca4821",
		},
		{
			name: "skip files and dirs",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: map[string]int{
					"alpine": 1,
					"debian": 1,
				},
				skipFiles: []string{"app/deployment.yaml"},
				skipDirs:  []string{"usr/java"},
				policy:    []string{"testdata/policy"},
			},
			want: "sha256:b92c36d74172cbe3b7c07e169d9f594cd7822e8e95cb7bc1cd957ac17be62a4a",
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
			artifactOpt := artifact.Option{
				SkipFiles: tt.args.skipFiles,
				SkipDirs:  tt.args.skipDirs,
			}
			scannerOpt := config.ScannerOption{
				FilePatterns: tt.args.patterns,
				PolicyPaths:  tt.args.policy,
				DataPaths:    tt.args.data,
			}
			got, err := CalcKey(tt.args.key, tt.args.analyzerVersions, tt.args.hookVersions, artifactOpt, scannerOpt)
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
