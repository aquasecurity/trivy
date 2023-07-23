package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

func TestCalcKey(t *testing.T) {
	type args struct {
		key              string
		analyzerVersions analyzer.Versions
		hookVersions     map[string]int
		skipFiles        []string
		skipDirs         []string
		patterns         []string
		policy           []string
		data             []string
		secretConfigPath string
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
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:c720b502991465ea11929cfefc71cf4b5aeaa9a8c0ae59fdaf597f957f5cdb18",
		},
		{
			name: "with disabled analyzer",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 0,
						"redhat": 2,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
			},
			want: "sha256:d63724cc72729edd3c81205739d64fcb414a4e6345dd4dde7f0fe6bdd56bedf9",
		},
		{
			name: "with empty slice file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{},
			},
			want: "sha256:9f7afa4d27c4c4f371dc6bb47bcc09e7a4a00b1d870e8156f126e35d8f6522e6",
		},
		{
			name: "with single empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{""},
			},
			want: "sha256:bcfc5da13ef9bf0b85e719584800a010063474546f1051a781b78bd83de01102",
		},
		{
			name: "with single non empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{"test"},
			},
			want: "sha256:8c9750b8eca507628417f21d7db707a7876d2e22c3e75b13f31a795af4051c57",
		},
		{
			name: "with non empty followed by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{"test", ""},
			},
			want: "sha256:71abf09bf1422531e2838db692b80f9b9f48766f56b7d3d02aecdb36b019e103",
		},
		{
			name: "with non empty preceded by empty string in file patterns",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				patterns: []string{"", "test"},
			},
			want: "sha256:71abf09bf1422531e2838db692b80f9b9f48766f56b7d3d02aecdb36b019e103",
		},
		{
			name: "with policy",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				policy: []string{"testdata/policy"},
			},
			want: "sha256:9602d5ef5af086112cc9fae8310390ed3fb79f4b309d8881b9807e379c8dfa57",
		},
		{
			name: "with policy file",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				policy: []string{"testdata/policy/test.rego"},
			},
			want: "sha256:9602d5ef5af086112cc9fae8310390ed3fb79f4b309d8881b9807e379c8dfa57",
		},
		{
			name: "skip files and dirs",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				skipFiles: []string{"app/deployment.yaml"},
				skipDirs:  []string{"usr/java"},
				policy:    []string{"testdata/policy"},
			},
			want: "sha256:363f70f4ee795f250873caea11c2fc94ef12945444327e7e2f8a99e3884695e0",
		},
		{

			name: "secret config",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
				secretConfigPath: "testdata/trivy-secret.yaml",
			},
			want: "sha256:d3fb9503f2851ae9bdb250b7ef55c00c0bfa1250b19d4d398a9219c2c0e20958",
		},
		{

			name: "secret config file doesn't exist",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				hookVersions: map[string]int{
					"python-pkg": 1,
				},
				secretConfigPath: "trivy-secret.yaml",
			},
			want: "sha256:c720b502991465ea11929cfefc71cf4b5aeaa9a8c0ae59fdaf597f957f5cdb18",
		},
		{
			name: "with policy/non-existent dir",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				policy: []string{"policydir"},
			},
			wantErr: "file \"policydir\" stat error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactOpt := artifact.Option{
				SkipFiles:    tt.args.skipFiles,
				SkipDirs:     tt.args.skipDirs,
				FilePatterns: tt.args.patterns,

				MisconfScannerOption: misconf.ScannerOption{
					PolicyPaths: tt.args.policy,
					DataPaths:   tt.args.data,
				},

				SecretScannerOption: analyzer.SecretScannerOption{
					ConfigPath: tt.args.secretConfigPath,
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
