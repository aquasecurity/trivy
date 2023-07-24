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
		thirdPartyOSPkgs []string
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
			want: "sha256:e1869e8e674badac5f3f940a1a67c486a9b05b7b3286d51eeb61915fa9c9058f",
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
			want: "sha256:2b0965d8bab4d008f4d64161943365518310b7b26b3e9ccf2a011f3e2c8306eb",
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
			want: "sha256:f947b945d3b3f494fa8f871eb627cc7b4a223733cfb90992b17e4aa13fb359be",
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
			want: "sha256:a408cd958b192d07f1283e4a1548da0c458a9bf15568ae07933b10d0fe3b9ae1",
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
			want: "sha256:6580886916ab4b096242b312b000ea3da31bc376048e08c1cde0a45b8ef8fb51",
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
			want: "sha256:95b2152ce27471ba076e1da987a5efd62372076a833874f9d04c8c5d16dbfb28",
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
			want: "sha256:95b2152ce27471ba076e1da987a5efd62372076a833874f9d04c8c5d16dbfb28",
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
			want: "sha256:46538f674ad7373e6f63273fc09edabe63085eaa37c95abb40a7a0ed14160db5",
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
			want: "sha256:46538f674ad7373e6f63273fc09edabe63085eaa37c95abb40a7a0ed14160db5",
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
			want: "sha256:2bf2573e9f381b81c1d7563b0ef2f1c78cc3cf8d626ff31c6c1aa934b59f5a71",
		},
		{
			name: "third party os pkgs",
			args: args{
				key: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				analyzerVersions: analyzer.Versions{
					Analyzers: map[string]int{
						"alpine": 1,
						"debian": 1,
					},
				},
				thirdPartyOSPkgs: []string{"busybox"},
			},
			want: "sha256:0c131167d441f8131d263f9ff6b0eb429b63da2e9923bb73992d87b1d80feaf1",
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
				SkipFiles:        tt.args.skipFiles,
				SkipDirs:         tt.args.skipDirs,
				FilePatterns:     tt.args.patterns,
				ThirdPartyOSPkgs: tt.args.thirdPartyOSPkgs,

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
