package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
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
			want: "sha256:9b81e0bf3aa7809a0f41bc696f353fca5645bcb63b975ab30e23d81886df2e61",
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
			want: "sha256:7d91b2623ae4b5641a1f36efa59c774231efe8c28c27a03869894fd49b047fe8",
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
			want: "sha256:5c7f1555e95fc60cdaa7e92e99aee15ee7be356fad9e83f1c24a3be06713a5a8",
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
			want: "sha256:5c7f1555e95fc60cdaa7e92e99aee15ee7be356fad9e83f1c24a3be06713a5a8",
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
			wantErr: "hash dir error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactOpt := artifact.Option{
				SkipFiles:    tt.args.skipFiles,
				SkipDirs:     tt.args.skipDirs,
				FilePatterns: tt.args.patterns,

				MisconfScannerOption: config.ScannerOption{
					PolicyPaths: tt.args.policy,
					DataPaths:   tt.args.data,
				},
			}
			got, err := CalcKey(tt.args.key, tt.args.analyzerVersions, tt.args.hookVersions, artifactOpt)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
