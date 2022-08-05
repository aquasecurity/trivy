package commands

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_showVersion(t *testing.T) {
	type args struct {
		cacheDir     string
		outputFormat string
		version      string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path, table output",
			args: args{
				outputFormat: "table",
				version:      "v1.2.3",
				cacheDir:     "testdata",
			},
			want: `Version: v1.2.3
Vulnerability DB:
  Version: 2
  UpdatedAt: 2022-03-02 06:07:07.99504083 +0000 UTC
  NextUpdate: 2022-03-02 12:07:07.99504023 +0000 UTC
  DownloadedAt: 2022-03-02 10:03:38.383312 +0000 UTC
`,
		},
		{
			name: "sad path, bogus cache dir",
			args: args{
				outputFormat: "json",
				version:      "1.2.3",
				cacheDir:     "/foo/bar/bogus",
			},
			want: `{"Version":"1.2.3"}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := new(bytes.Buffer)
			showVersion(tt.args.cacheDir, tt.args.outputFormat, tt.args.version, got)
			assert.Equal(t, tt.want, got.String(), tt.name)
		})
	}
}

//Check flag and command for print version
func TestPrintVersion(t *testing.T) {
	tableOutput := `Version: test
Vulnerability DB:
  Version: 2
  UpdatedAt: 2022-03-02 06:07:07.99504083 +0000 UTC
  NextUpdate: 2022-03-02 12:07:07.99504023 +0000 UTC
  DownloadedAt: 2022-03-02 10:03:38.383312 +0000 UTC
`

	jsonOutput := `{"Version":"test","VulnerabilityDB":{"Version":2,"NextUpdate":"2022-03-02T12:07:07.99504023Z","UpdatedAt":"2022-03-02T06:07:07.99504083Z","DownloadedAt":"2022-03-02T10:03:38.383312Z"}}
`
	tests := []struct {
		name      string
		arguments []string // 1st argument is path to trivy binaries
		want      string
	}{
		{
			name:      "happy path. '-v' flag is used",
			arguments: []string{"-v", "--cache-dir", "testdata"},
			want:      tableOutput,
		},
		{
			name:      "happy path. '-version' flag is used",
			arguments: []string{"--version", "--cache-dir", "testdata"},
			want:      tableOutput,
		},
		{
			name:      "happy path. 'version' command is used",
			arguments: []string{"--cache-dir", "testdata", "version"},
			want:      tableOutput,
		},
		{
			name:      "happy path. 'version', '--format json' flags are used",
			arguments: []string{"--cache-dir", "testdata", "version", "--format", "json"},
			want:      jsonOutput,
		},
		{
			name:      "happy path. '-v', '--format json' flags are used",
			arguments: []string{"--cache-dir", "testdata", "-v", "--format", "json"},
			want:      jsonOutput,
		},
		{
			name:      "happy path. '--version', '--format json' flags are used",
			arguments: []string{"--cache-dir", "testdata", "--version", "--format", "json"},
			want:      jsonOutput,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := new(bytes.Buffer)
			app := NewApp("test")
			SetOut(got)
			app.SetArgs(test.arguments)

			err := app.Execute()
			require.NoError(t, err)
			assert.Equal(t, test.want, got.String())
		})
	}
}

//Check that options from config file and envs work correctly
func TestConfigFileAndEnv(t *testing.T) {
	type wantValues = struct {
		debug     bool
		timeout   time.Duration
		redisCert string
		skipDirs  []string
		vulnType  []string
	}
	tests := []struct {
		name      string
		arguments []string
		envs      map[string]string
		want      wantValues
	}{
		{
			name:      "happy path. Without config file or envs",
			arguments: []string{"image"},
			want: wantValues{
				timeout:  time.Second * 300,
				skipDirs: []string{},
				vulnType: []string{types.VulnTypeOS + "," + types.VulnTypeLibrary},
			},
		},
		{
			name:      "happy path.Used env",
			arguments: []string{"image"},
			envs: map[string]string{
				"TRIVY_DEBUG":      "true",
				"TRIVY_TIMEOUT":    "10m",
				"TRIVY_REDIS_CERT": "ca-cert.pem",
				"TRIVY_SKIP_DIRS":  "envDir1,envDir2",
				"TRIVY_VULN_TYPE":  "library",
			},
			want: wantValues{
				debug:     true,
				timeout:   time.Minute * 10,
				redisCert: "ca-cert.pem",
				skipDirs:  []string{"envDir1,envDir2"},
				vulnType:  []string{types.VulnTypeLibrary},
			},
		},
		{
			name:      "happy path. Used config file",
			arguments: []string{"--config", "./testdata/trivy.yaml", "image"},
			want: wantValues{
				debug:     false,
				timeout:   time.Minute * 20,
				redisCert: "ca-conf-cert.pem",
				skipDirs:  []string{"dir1", "dir2"},
				vulnType:  []string{types.VulnTypeOS},
			},
		},
		{
			name:      "happy path.Used env and config file", // env takes precedence over config file
			arguments: []string{"--config", "./testdata/trivy.yaml", "image"},
			envs: map[string]string{
				"TRIVY_DEBUG":      "true",
				"TRIVY_TIMEOUT":    "10m",
				"TRIVY_REDIS_CERT": "ca-cert.pem",
				"TRIVY_SKIP_DIRS":  "envDir1,envDir2",
				"TRIVY_VULN_TYPE":  "library",
			},
			want: wantValues{
				debug:     true,
				timeout:   time.Minute * 10,
				redisCert: "ca-cert.pem",
				skipDirs:  []string{"envDir1,envDir2"},
				vulnType:  []string{types.VulnTypeLibrary},
			},
		},
		{
			name:      "happy path.Used command and env", // command takes precedence over env or config file
			arguments: []string{"--timeout", "12m", "--skip-dirs", "dir1,dir2", "--vuln-type", "os", "image"},
			envs: map[string]string{
				"TRIVY_DEBUG":     "true",
				"TRIVY_TIMEOUT":   "10m",
				"TRIVY_SKIP_DIRS": "envDir1,envDir2",
				"TRIVY_VULN_TYPE": "library",
			},
			want: wantValues{
				debug:    true,
				timeout:  time.Minute * 12,
				skipDirs: []string{"dir1", "dir2"},
				vulnType: []string{types.VulnTypeOS},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// set envs
			oldEnvs := map[string]string{}
			for k, v := range test.envs {
				oldEnvs[k] = os.Getenv(k)
				err := os.Setenv(k, v)
				assert.NoError(t, err)
			}
			defer func() {
				for k, v := range oldEnvs {
					err := os.Setenv(k, v)
					assert.NoError(t, err)
				}
				// reset viper after each test
				viper.Reset()
			}()

			// create buffer to not show cli recommendation in test result
			got := new(bytes.Buffer)
			app := NewApp("test")
			SetOut(got)
			app.SetArgs(test.arguments)

			// subcommands run without commands
			// this error is expected
			err := app.Execute()
			require.NotNil(t, err)

			// compare flag values
			assert.Equal(t, test.want.debug, viper.GetBool(flag.DebugFlag.ConfigName), "Check debug flag")
			assert.Equal(t, test.want.timeout, viper.GetDuration(flag.TimeoutFlag.ConfigName), "Check timeout flag")
			assert.Equal(t, test.want.redisCert, viper.GetString(flag.RedisCertFlag.ConfigName), "Check redis-cert flag")
			assert.Equal(t, test.want.skipDirs, viper.GetStringSlice(flag.SkipDirsFlag.ConfigName), "Check skip-dirs flag")
			assert.Equal(t, test.want.vulnType, viper.GetStringSlice(flag.VulnTypeFlag.ConfigName), "Check vuln-type flag")
		})
	}
}
