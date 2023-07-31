package commands

import (
	"bytes"
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
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
Java DB:
  Version: 1
  UpdatedAt: 2023-03-14 00:47:02.774253754 +0000 UTC
  NextUpdate: 2023-03-17 00:47:02.774253254 +0000 UTC
  DownloadedAt: 2023-03-14 03:04:55.058541039 +0000 UTC
Policy Bundle:
  Digest: sha256:19a017cdc798631ad42f6f4dce823d77b2989128f0e1a7f9bc83ae3c59024edd
  DownloadedAt: 2023-03-02 01:06:08.191725 +0000 UTC
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

// Check flag and command for print version
func TestPrintVersion(t *testing.T) {
	tableOutput := `Version: test
Vulnerability DB:
  Version: 2
  UpdatedAt: 2022-03-02 06:07:07.99504083 +0000 UTC
  NextUpdate: 2022-03-02 12:07:07.99504023 +0000 UTC
  DownloadedAt: 2022-03-02 10:03:38.383312 +0000 UTC
Java DB:
  Version: 1
  UpdatedAt: 2023-03-14 00:47:02.774253754 +0000 UTC
  NextUpdate: 2023-03-17 00:47:02.774253254 +0000 UTC
  DownloadedAt: 2023-03-14 03:04:55.058541039 +0000 UTC
Policy Bundle:
  Digest: sha256:19a017cdc798631ad42f6f4dce823d77b2989128f0e1a7f9bc83ae3c59024edd
  DownloadedAt: 2023-03-02 01:06:08.191725 +0000 UTC
`
	jsonOutput := `{"Version":"test","VulnerabilityDB":{"Version":2,"NextUpdate":"2022-03-02T12:07:07.99504023Z","UpdatedAt":"2022-03-02T06:07:07.99504083Z","DownloadedAt":"2022-03-02T10:03:38.383312Z"},"JavaDB":{"Version":1,"NextUpdate":"2023-03-17T00:47:02.774253254Z","UpdatedAt":"2023-03-14T00:47:02.774253754Z","DownloadedAt":"2023-03-14T03:04:55.058541039Z"},"PolicyBundle":{"Digest":"sha256:19a017cdc798631ad42f6f4dce823d77b2989128f0e1a7f9bc83ae3c59024edd","DownloadedAt":"2023-03-01T17:06:08.191725-08:00"}}
`
	tests := []struct {
		name      string
		arguments []string // 1st argument is path to trivy binaries
		want      string
	}{
		{
			name: "happy path. '-v' flag is used",
			arguments: []string{
				"-v",
				"--cache-dir",
				"testdata",
			},
			want: tableOutput,
		},
		{
			name: "happy path. '-version' flag is used",
			arguments: []string{
				"--version",
				"--cache-dir",
				"testdata",
			},
			want: tableOutput,
		},
		{
			name: "happy path. 'version' command is used",
			arguments: []string{
				"--cache-dir",
				"testdata",
				"version",
			},
			want: tableOutput,
		},
		{
			name: "happy path. 'version', '--format json' flags are used",
			arguments: []string{
				"--cache-dir",
				"testdata",
				"version",
				"--format",
				"json",
			},
			want: jsonOutput,
		},
		{
			name: "happy path. '-v', '--format json' flags are used",
			arguments: []string{
				"--cache-dir",
				"testdata",
				"-v",
				"--format",
				"json",
			},
			want: jsonOutput,
		},
		{
			name: "happy path. '--version', '--format json' flags are used",
			arguments: []string{
				"--cache-dir",
				"testdata",
				"--version",
				"--format",
				"json",
			},
			want: jsonOutput,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := new(bytes.Buffer)
			app := NewApp("test")
			app.SetOut(got)
			app.SetArgs(test.arguments)

			err := app.Execute()
			require.NoError(t, err)
			assert.Equal(t, test.want, got.String())
		})
	}
}

func TestFlags(t *testing.T) {
	type want struct {
		format     types.Format
		severities []dbTypes.Severity
	}
	tests := []struct {
		name      string
		arguments []string // 1st argument is path to trivy binaries
		want      want
		wantErr   string
	}{
		{
			name: "happy path",
			arguments: []string{
				"test",
			},
			want: want{
				format: types.FormatTable,
				severities: []dbTypes.Severity{
					dbTypes.SeverityUnknown,
					dbTypes.SeverityLow,
					dbTypes.SeverityMedium,
					dbTypes.SeverityHigh,
					dbTypes.SeverityCritical,
				},
			},
		},
		{
			name: "happy path with comma-separated severities",
			arguments: []string{
				"test",
				"--severity",
				"LOW,MEDIUM",
			},
			want: want{
				format: types.FormatTable,
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityMedium,
				},
			},
		},
		{
			name: "happy path with repeated severities",
			arguments: []string{
				"test",
				"--severity",
				"LOW",
				"--severity",
				"HIGH",
			},
			want: want{
				format: types.FormatTable,
				severities: []dbTypes.Severity{
					dbTypes.SeverityLow,
					dbTypes.SeverityHigh,
				},
			},
		},
		{
			name: "happy path with json",
			arguments: []string{
				"test",
				"--format",
				"json",
				"--severity",
				"CRITICAL",
			},
			want: want{
				format: types.FormatJSON,
				severities: []dbTypes.Severity{
					dbTypes.SeverityCritical,
				},
			},
		},
		{
			name: "invalid format",
			arguments: []string{
				"test",
				"--format",
				"foo",
			},
			wantErr: `invalid argument "foo" for "-f, --format" flag`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			globalFlags := flag.NewGlobalFlagGroup()
			rootCmd := NewRootCommand("dev", globalFlags)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetOut(io.Discard)

			flags := &flag.Flags{
				ReportFlagGroup: flag.NewReportFlagGroup(),
			}
			cmd := &cobra.Command{
				Use: "test",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Bind
					require.NoError(t, flags.Bind(cmd))

					options, err := flags.ToOptions("dev", args, globalFlags)
					require.NoError(t, err)

					assert.Equal(t, tt.want.format, options.Format)
					assert.Equal(t, tt.want.severities, options.Severities)
					return nil
				},
			}
			flags.AddFlags(cmd)
			rootCmd.AddCommand(cmd)

			rootCmd.SetArgs(tt.arguments)

			err := rootCmd.Execute()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
