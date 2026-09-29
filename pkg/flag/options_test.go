package flag_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFlag_Parse(t *testing.T) {
	type kv struct {
		key   string
		value any
	}
	tests := []struct {
		name    string
		flag    *kv
		env     *kv
		want    []string
		wantErr string
	}{
		{
			name: "flag, string slice",
			flag: &kv{
				key: "scan.scanners",
				value: []string{
					"vuln",
					"misconfig",
				},
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "env, string",
			env: &kv{
				key:   "TRIVY_SCANNERS",
				value: "vuln,misconfig",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "flag, alias",
			flag: &kv{
				key:   "scan.security-checks",
				value: "vulnerability,config",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "env, alias",
			env: &kv{
				key:   "TRIVY_SECURITY_CHECKS",
				value: "vulnerability,config",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "flag, invalid value",
			flag: &kv{
				key:   "scan.scanners",
				value: "vuln,invalid",
			},
			wantErr: `invalid argument "[vuln invalid]" for "--scanners" flag`,
		},
		{
			name: "env, invalid value",
			env: &kv{
				key:   "TRIVY_SCANNERS",
				value: "vuln,invalid",
			},
			wantErr: `invalid argument "[vuln invalid]" for "--scanners" flag`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			if tt.flag != nil {
				viper.Set(tt.flag.key, tt.flag.value)
			} else {
				t.Setenv(tt.env.key, tt.env.value.(string))
			}

			app := &cobra.Command{}
			f := flag.ScannersFlag.Clone()
			f.Add(app)
			require.NoError(t, f.Bind(app))

			err := f.Parse()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, f.Value())
		})
	}
}

func setValue[T comparable](key string, value T) {
	if !lo.IsEmpty(value) {
		viper.Set(key, value)
	}
}

func setSliceValue[T any](key string, value []T) {
	if len(value) > 0 {
		viper.Set(key, value)
	}
}

type Output struct {
	b *bytes.Buffer
}

func (o Output) Messages() []string {
	var messages []string
	for line := range strings.SplitSeq(o.b.String(), "\n") {
		if line == "" {
			continue
		}
		ss := strings.Split(line, "\t")
		messages = append(messages, strings.Join(ss[2:], "\t"))
	}
	return messages
}

func newLogger(level slog.Level) Output {
	out := bytes.NewBuffer(nil)
	logger := log.New(log.NewHandler(out, &log.Options{Level: level}))
	log.SetDefault(logger)
	return Output{b: out}
}

// testFlagGroup is a simple FlagGroup for testing using existing flag definitions
type testFlagGroup struct {
	CacheDir         *flag.Flag[string]
	Quiet            *flag.Flag[bool]
	LicenseForbidden *flag.Flag[[]string]
}

func newTestFlagGroup() *testFlagGroup {
	return &testFlagGroup{
		CacheDir:         flag.CacheDirFlag.Clone(),
		Quiet:            flag.QuietFlag.Clone(),
		LicenseForbidden: flag.LicenseForbidden.Clone(),
	}
}

func (fg *testFlagGroup) Name() string {
	return "Test"
}

func (fg *testFlagGroup) Flags() []flag.Flagger {
	return []flag.Flagger{
		fg.CacheDir,
		fg.Quiet,
		fg.LicenseForbidden,
	}
}

func (fg *testFlagGroup) ToOptions(_ *flag.Options) error {
	// Not needed for testing
	return nil
}

// TestFlag_IsSet verifies that IsSet() correctly identifies whether a value was set
// via CLI flag, environment variable, or config file, and that defaults are handled
// properly for config-only flags
func TestFlag_IsSet(t *testing.T) {
	// wantFlag represents the expected state of a flag for testing
	type wantFlag[T any] struct {
		IsSet bool
		Value T
	}

	// wantFlags represents the expected state of all flags for testing
	type wantFlags struct {
		CacheDir         wantFlag[string]
		Quiet            wantFlag[bool]
		LicenseForbidden wantFlag[[]string]
	}

	tests := []struct {
		name       string
		cliArgs    []string
		envs       map[string]string
		configYAML string
		want       wantFlags
	}{
		{
			name: "nothing set - use defaults",
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: false, Value: flag.CacheDirFlag.Default},
				Quiet:            wantFlag[bool]{IsSet: false, Value: false},
				LicenseForbidden: wantFlag[[]string]{IsSet: false, Value: flag.LicenseForbidden.Default},
			},
		},
		{
			name: "CLI flags - all set",
			// Note: --license-forbidden is a config-only flag and cannot be set via CLI.
			// It will be ignored even when explicitly passed.
			cliArgs: []string{"--cache-dir", "/cli/cache", "-q", "--license-forbidden", "MIT"},
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: true, Value: "/cli/cache"},
				Quiet:            wantFlag[bool]{IsSet: true, Value: true},
				LicenseForbidden: wantFlag[[]string]{IsSet: false, Value: flag.LicenseForbidden.Default},
			},
		},
		{
			name: "environment variables - all set",
			envs: map[string]string{
				"TRIVY_CACHE_DIR":         "/env/cache",
				"TRIVY_QUIET":             "true",
				"TRIVY_LICENSE_FORBIDDEN": "MIT,Apache-2.0", // Will not be respected even when explicitly set, because ENVs are derived from flag.Name, and LicenseForbidden is a config-only flag (has no Name field).
			},
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: true, Value: "/env/cache"},
				Quiet:            wantFlag[bool]{IsSet: true, Value: true},
				LicenseForbidden: wantFlag[[]string]{IsSet: false, Value: flag.LicenseForbidden.Default},
			},
		},
		{
			name: "config file - all set",
			configYAML: `
cache:
  dir: /config/cache
quiet: true
license:
  forbidden:
    - MIT
    - Apache-2.0
`,
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: true, Value: "/config/cache"},
				Quiet:            wantFlag[bool]{IsSet: true, Value: true},
				LicenseForbidden: wantFlag[[]string]{IsSet: true, Value: []string{"MIT", "Apache-2.0"}},
			},
		},
		{
			name:    "CLI flags - only cache dir",
			cliArgs: []string{"--cache-dir", "/cli/cache"},
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: true, Value: "/cli/cache"},
				Quiet:            wantFlag[bool]{IsSet: false, Value: false},
				LicenseForbidden: wantFlag[[]string]{IsSet: false, Value: flag.LicenseForbidden.Default},
			},
		},
		{
			name: "config file - license forbidden empty array",
			configYAML: `
license:
  forbidden: []
`,
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: false, Value: flag.CacheDirFlag.Default},
				Quiet:            wantFlag[bool]{IsSet: false, Value: false},
				LicenseForbidden: wantFlag[[]string]{IsSet: true, Value: []string{}},
			},
		},
		{
			// When a YAML key has no value (e.g., "forbidden:"), viper treats it as nil
			// rather than an empty array. This means IsSet() returns false and the
			// default value is used. To explicitly set an empty array, use "forbidden: []".
			name: "config file - license forbidden empty value",
			configYAML: `
license:
  forbidden:
`,
			want: wantFlags{
				CacheDir:         wantFlag[string]{IsSet: false, Value: flag.CacheDirFlag.Default},
				Quiet:            wantFlag[bool]{IsSet: false, Value: false},
				LicenseForbidden: wantFlag[[]string]{IsSet: false, Value: flag.LicenseForbidden.Default},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			// Set up environment variables
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			// Set up config file if provided
			if tt.configYAML != "" {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "trivy.yaml")
				require.NoError(t, os.WriteFile(configPath, []byte(tt.configYAML), 0o644))

				viper.SetConfigFile(configPath)
				require.NoError(t, viper.ReadInConfig())
			}

			cmd := &cobra.Command{
				Use: "test",
				Run: func(_ *cobra.Command, _ []string) {},
			}
			// Ignore unknown flags to allow testing specific flags without defining all
			cmd.FParseErrWhitelist.UnknownFlags = true

			// Create a test flag group
			fg := newTestFlagGroup()
			testFlags := flag.Flags{fg}

			// Use AddFlags method from Flags type
			testFlags.AddFlags(cmd)

			// Parse CLI arguments
			require.NoError(t, cmd.ParseFlags(tt.cliArgs))

			// Bind flags
			require.NoError(t, testFlags.Bind(cmd))

			// Call ToOptions to parse flags automatically
			_, err := testFlags.ToOptions(tt.cliArgs)
			require.NoError(t, err)

			// Check all flags
			assert.Equal(t, tt.want.CacheDir.IsSet, fg.CacheDir.IsSet(), "CacheDir.IsSet mismatch")
			assert.Equal(t, tt.want.CacheDir.Value, fg.CacheDir.Value(), "CacheDir.Value mismatch")

			assert.Equal(t, tt.want.Quiet.IsSet, fg.Quiet.IsSet(), "Quiet.IsSet mismatch")
			assert.Equal(t, tt.want.Quiet.Value, fg.Quiet.Value(), "Quiet.Value mismatch")

			assert.Equal(t, tt.want.LicenseForbidden.IsSet, fg.LicenseForbidden.IsSet(), "LicenseForbidden.IsSet mismatch")
			assert.Equal(t, tt.want.LicenseForbidden.Value, fg.LicenseForbidden.Value(), "LicenseForbidden.Value mismatch")
		})
	}
}
