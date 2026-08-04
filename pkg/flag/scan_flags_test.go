package flag_test

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		skipDirs         []string
		skipFiles        []string
		offlineScan      bool
		scanners         string
		distro           string
		skipVersionCheck bool
		mavenMirrors     []flag.MavenMirror
	}
	tests := []struct {
		name      string
		args      []string
		fields    fields
		want      flag.ScanOptions
		assertion require.ErrorAssertionFunc
	}{
		{
			name:   "happy path",
			args:   []string{"alpine:latest"},
			fields: fields{},
			want: flag.ScanOptions{
				Target: "alpine:latest",
			},
			assertion: require.NoError,
		},
		{
			name: "happy path for configs",
			args: []string{"alpine:latest"},
			fields: fields{
				scanners: "misconfig",
			},
			want: flag.ScanOptions{
				Target:   "alpine:latest",
				Scanners: types.Scanners{types.MisconfigScanner},
			},
			assertion: require.NoError,
		},
		{
			name:      "without target (args)",
			args:      []string{},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "with two or more targets (args)",
			args: []string{
				"alpine:latest",
				"nginx:latest",
			},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "skip two files",
			fields: fields{
				skipFiles: []string{
					"file1",
					"file2",
				},
			},
			want: flag.ScanOptions{
				SkipFiles: []string{
					"file1",
					"file2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "skip two folders",
			fields: fields{
				skipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			want: flag.ScanOptions{
				SkipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "offline scan",
			fields: fields{
				offlineScan: true,
			},
			want: flag.ScanOptions{
				OfflineScan: true,
			},
			assertion: require.NoError,
		},
		{
			name: "happy path `distro` flag",
			fields: fields{
				distro: "alpine/3.20",
			},
			want: flag.ScanOptions{
				Distro: ftypes.OS{
					Family: "alpine",
					Name:   "3.20",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "sad distro flag",
			fields: fields{
				distro: "sad",
			},
			assertion: require.Error,
		},
		{
			name: "skip version check flag",
			fields: fields{
				skipVersionCheck: true,
			},
			want: flag.ScanOptions{
				SkipVersionCheck: true,
			},
			assertion: require.NoError,
		},
		{
			name: "maven mirrors from config file reach ScanOptions with their case preserved",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://example.com/Repository/Maven2/",
						Targets: []string{"https://my-internal-mirror/Maven2/"},
					},
				},
			},
			want: flag.ScanOptions{
				MavenMirrors: map[string][]string{
					"https://example.com/Repository/Maven2": {"https://my-internal-mirror/Maven2/"},
				},
			},
			assertion: require.NoError,
		},
		{
			name: "unparsable maven mirror URL is rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://repo.maven.apache.org/maven2/",
						Targets: []string{"http://[::1"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			name: "unparsable maven repository URL is rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "central",
						Targets: []string{"https://my-internal-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			name: "non-http(s) maven mirror scheme is rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://repo.maven.apache.org/maven2/",
						Targets: []string{"ftp://my-internal-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			name: "empty maven mirror target list is rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source: "https://repo.maven.apache.org/maven2/",
					},
				},
			},
			assertion: require.Error,
		},
		{
			name: "maven repository configured twice is rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://repo.maven.apache.org/maven2/",
						Targets: []string{"https://my-internal-mirror/maven2/"},
					},
					{
						Source:  "https://repo.maven.apache.org/maven2",
						Targets: []string{"https://backup-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			// The parser matches repositories without their credentials, so these two
			// would collapse into a single entry.
			name: "maven repositories differing only by credentials are rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://first:pass@nexus.example.com/maven2/",
						Targets: []string{"https://my-internal-mirror/maven2/"},
					},
					{
						Source:  "https://second:pass@nexus.example.com/maven2/",
						Targets: []string{"https://backup-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			// The path is cleaned before matching, so these two would collapse as well.
			name: "maven repositories differing only by path segments are rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://nexus.example.com/nexus/maven2",
						Targets: []string{"https://my-internal-mirror/maven2/"},
					},
					{
						Source:  "https://nexus.example.com//nexus/./maven2/",
						Targets: []string{"https://backup-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
		{
			// The host is case-insensitive, so these two would collapse as well.
			name: "maven repositories differing only by host case are rejected",
			fields: fields{
				mavenMirrors: []flag.MavenMirror{
					{
						Source:  "https://nexus.example.com/maven2/",
						Targets: []string{"https://my-internal-mirror/maven2/"},
					},
					{
						Source:  "https://Nexus.Example.COM/maven2/",
						Targets: []string{"https://backup-mirror/maven2/"},
					},
				},
			},
			assertion: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			setSliceValue(flag.SkipDirsFlag.ConfigName, tt.fields.skipDirs)
			setSliceValue(flag.SkipFilesFlag.ConfigName, tt.fields.skipFiles)
			setValue(flag.OfflineScanFlag.ConfigName, tt.fields.offlineScan)
			setValue(flag.ScannersFlag.ConfigName, tt.fields.scanners)
			setValue(flag.DistroFlag.ConfigName, tt.fields.distro)
			setValue(flag.SkipVersionCheckFlag.ConfigName, tt.fields.skipVersionCheck)
			if len(tt.fields.mavenMirrors) > 0 {
				viper.Set(flag.MavenMirrorsFlag.ConfigName, tt.fields.mavenMirrors)
			}

			// Assert options
			f := &flag.ScanFlagGroup{
				SkipDirs:         flag.SkipDirsFlag.Clone(),
				SkipFiles:        flag.SkipFilesFlag.Clone(),
				OfflineScan:      flag.OfflineScanFlag.Clone(),
				Scanners:         flag.ScannersFlag.Clone(),
				DistroFlag:       flag.DistroFlag.Clone(),
				SkipVersionCheck: flag.SkipVersionCheckFlag.Clone(),
				MavenMirrors:     flag.MavenMirrorsFlag.Clone(),
			}

			flags := flag.Flags{f}
			got, err := flags.ToOptions(tt.args)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got.ScanOptions)
		})
	}
}

// TestScanFlagGroup_ToOptions_mavenMirrorsYAML parses the Maven mirrors from a real config
// file, since viper lowercases the keys it reads from one. A repository URL is a value here
// rather than a key, so its case-sensitive path must survive the round trip.
func TestScanFlagGroup_ToOptions_mavenMirrorsYAML(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		want      map[string][]string
		assertion require.ErrorAssertionFunc
	}{
		{
			name: "case-sensitive repository path is preserved",
			config: `
scan:
  maven:
    mirrors:
      - source: https://example.com/Repository/Maven2/
        targets:
          - https://mirror.example.com/Maven2/
          - https://backup.example.com/maven2/
`,
			want: map[string][]string{
				"https://example.com/Repository/Maven2": {
					"https://mirror.example.com/Maven2/",
					"https://backup.example.com/maven2/",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "mirrors of an unexpected type are rejected",
			config: `
scan:
  maven:
    mirrors: https://mirror.example.com/maven2/
`,
			assertion: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			viper.SetConfigType("yaml")
			require.NoError(t, viper.ReadConfig(strings.NewReader(tt.config)))

			f := &flag.ScanFlagGroup{
				MavenMirrors: flag.MavenMirrorsFlag.Clone(),
			}
			flags := flag.Flags{f}
			got, err := flags.ToOptions(nil)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got.ScanOptions.MavenMirrors)
		})
	}
}
