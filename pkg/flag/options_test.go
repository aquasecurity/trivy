package flag

import (
	"github.com/aquasecurity/trivy/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func Test_getStringSlice(t *testing.T) {
	type env struct {
		key   string
		value string
	}
	tests := []struct {
		name      string
		flag      *Flag
		flagValue interface{}
		env       env
		want      []string
	}{
		{
			name:      "happy path. Empty value",
			flag:      &ScannersFlag,
			flagValue: "",
			want:      nil,
		},
		{
			name:      "happy path. String value",
			flag:      &ScannersFlag,
			flagValue: "license,vuln",
			want: []string{
				string(types.LicenseScanner),
				string(types.VulnerabilityScanner),
			},
		},
		{
			name: "happy path. Slice value",
			flag: &ScannersFlag,
			flagValue: []string{
				"license",
				"secret",
			},
			want: []string{
				string(types.LicenseScanner),
				string(types.SecretScanner),
			},
		},
		{
			name: "happy path. Env value",
			flag: &ScannersFlag,
			env: env{
				key:   "TRIVY_SECURITY_CHECKS",
				value: "rbac,config",
			},
			want: []string{
				string(types.RBACScanner),
				string(types.MisconfigScanner),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env.key == "" {
				viper.Set(tt.flag.ConfigName, tt.flagValue)
			} else {
				err := viper.BindEnv(tt.flag.ConfigName, tt.env.key)
				assert.NoError(t, err)

				t.Setenv(tt.env.key, tt.env.value)
			}

			sl := getStringSlice(tt.flag)
			assert.Equal(t, tt.want, sl)

			viper.Reset()
		})
	}
}

func Test_Align(t *testing.T) {
	tests := []struct {
		name         string
		options      *Options
		wantScanners types.Scanners
		wantLogs     []string
	}{
		{
			name: "table format with pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatTable,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
						types.PkgScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			wantLogs: []string{
				`"--scanners pkg" cannot be used with "--format table". Try "--format json" or other formats.`,
			},
		},
		{
			name: "--dependency-tree flag without pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format:         types.FormatJSON,
					DependencyTree: true,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.VulnerabilityScanner,
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--dependency-tree" enables "--scanners pkg".`,
			},
		},
		{
			name: "sarif format without pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatSarif,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.VulnerabilityScanner,
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--format sarif" automatically enables "--scanners pkg" to get locations.`,
			},
		},
		{
			name: "spdx format without pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatSPDX,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--format spdx" automatically enables "--scanners pkg".`,
				`"--format spdx" automatically disables security scanning.`,
			},
		},
		{
			name: "spdx format with only pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatSPDX,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.PkgScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.PkgScanner,
			},
		},
		{
			name: "spdx format with secret scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatSPDX,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.SecretScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--format spdx" automatically enables "--scanners pkg".`,
				`"--format spdx" automatically disables "--scanners license,config,secret".`,
			},
		},
		{
			name: "cyclonedx format without pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatCycloneDX,
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--format cyclonedx" automatically enables "--scanners pkg".`,
				`"--format cyclonedx" automatically disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the CycloneDX report.`,
			},
		},
		{
			name: "k8s target, cyclonedx format without pkg scanner",
			options: &Options{
				ReportOptions: ReportOptions{
					Format: types.FormatCycloneDX,
				},
				K8sOptions: K8sOptions{
					Components: []string{
						"workload",
						"infra",
					},
				},
				ScanOptions: ScanOptions{
					Scanners: types.Scanners{
						types.VulnerabilityScanner,
					},
				},
			},
			wantScanners: types.Scanners{
				types.PkgScanner,
			},
			wantLogs: []string{
				`"--format cyclonedx" automatically enables "--scanners pkg".`,
				`"k8s with --format cyclonedx" automatically disables security scanning.`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := zap.DebugLevel
			core, obs := observer.New(level)
			log.Logger = zap.New(core).Sugar()

			tt.options.Align()
			assert.Equal(t, tt.wantScanners, tt.options.Scanners)

			// Assert log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.wantLogs, gotMessages, tt.name)
		})
	}
}
