package cache

import (
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
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
		secretConfig     *secret.Config
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
			want: "sha256:486e797e3bab0e3cd5441eb193fef070742c45964564dcee1c9739461e35a457",
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
			want: "sha256:03646c00b9fa1b4663a82130487634dc6b45da342583d76d35a9efd786ba651e",
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
			want: "sha256:58a21644d4848791cb25e847a87c28783211c57ca7686569371dc64be326e71a",
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
			want: "sha256:3379fa38aa43d84ad4602a516303f8f8b67e6da54ed0741def7f8b824857f936",
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
			want: "sha256:556094befff08bfac9ae30dde469eee8d779b35adc11fe1146863a5481e60294",
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
			want: "sha256:62cc082c16d6509eedc07bc74d6380c84093ecb89ca21499fa8e399cab20dcdd",
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
			want: "sha256:62cc082c16d6509eedc07bc74d6380c84093ecb89ca21499fa8e399cab20dcdd",
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
			want: "sha256:4af92d2d238eb97171b436582fecaf1350c694c75a2a3a5993dd5f6f63797182",
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
			want: "sha256:4af92d2d238eb97171b436582fecaf1350c694c75a2a3a5993dd5f6f63797182",
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
			want: "sha256:0e26546849a11898031f0dfaf3b60e5fa811678b75a69993bc9c82b150e2c978",
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
				secretConfig: &secret.Config{
					DisableAllowRuleIDs: []string{
						"example",
						"usr-dirs",
					},
				},
			},
			want: "sha256:1f154a2848ad3ce519bda7f6f7d90886f7ccce63c875e9a618a38b8cf0050204",
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
					Config: tt.args.secretConfig,
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
