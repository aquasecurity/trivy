package commands

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
)

func Test_showVersion(t *testing.T) {
	type args struct {
		cacheDir     string
		outputFormat string
		version      string
	}
	tests := []struct {
		name           string
		args           args
		createDB       bool
		expectedOutput string
	}{
		{
			name: "happy path, table output",
			args: args{
				outputFormat: "table",
				version:      "v1.2.3",
			},
			expectedOutput: `Version: v1.2.3
Vulnerability DB:
  Version: 42
  UpdatedAt: 2020-03-16 23:40:20 +0000 UTC
  NextUpdate: 2020-03-16 23:57:00 +0000 UTC
  DownloadedAt: 2020-03-16 23:40:20 +0000 UTC
`,
			createDB: true,
		},
		{
			name: "happy path, JSON output",
			args: args{
				outputFormat: "json",
				version:      "1.2.3",
			},
			expectedOutput: `{"Version":"1.2.3","VulnerabilityDB":{"Version":42,"NextUpdate":"2020-03-16T23:57:00Z","UpdatedAt":"2020-03-16T23:40:20Z","DownloadedAt":"2020-03-16T23:40:20Z"}}
`,
			createDB: true,
		},
		{
			name: "sad path, no DB is available",
			args: args{
				outputFormat: "json",
				version:      "1.2.3",
			},
			expectedOutput: `{"Version":"1.2.3"}
`,
		},
		{
			name: "sad path, bogus cache dir",
			args: args{
				outputFormat: "json",
				version:      "1.2.3",
				cacheDir:     "/foo/bar/bogus",
			},
			expectedOutput: `{"Version":"1.2.3"}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cacheDir string
			switch {
			case tt.args.cacheDir != "":
				cacheDir = tt.args.cacheDir
			default:
				cacheDir, _ = os.MkdirTemp("", "Test_showVersion-*")
				defer os.RemoveAll(cacheDir)
			}

			if tt.createDB {
				fs := afero.NewOsFs()
				err := os.MkdirAll(filepath.Join(cacheDir, "db"), os.ModePerm)
				require.NoError(t, err)
				metadataFile := filepath.Join(cacheDir, "db", "metadata.json")

				b, err := json.Marshal(metadata.Metadata{
					Version:      42,
					NextUpdate:   time.Unix(1584403020, 0),
					UpdatedAt:    time.Unix(1584402020, 0),
					DownloadedAt: time.Unix(1584402020, 0),
				})
				require.NoError(t, err)
				err = afero.WriteFile(fs, metadataFile, b, 0600)
				require.NoError(t, err)
			}

			fw := new(bytes.Buffer)
			showVersion(cacheDir, tt.args.outputFormat, tt.args.version, fw)
			assert.Equal(t, tt.expectedOutput, fw.String(), tt.name)
		})
	}
}

//Check flag and command for print version
func TestPrintVersion(t *testing.T) {
	tableVersion := "tableVersion"
	jsonVersion := "jsonVersion"
	tests := []struct {
		name        string
		arguments   []string // 1st argument is path to trivy binaries
		wantVersion string
		wantError   string
	}{
		{
			name:        "happy path. '-v' flag is used",
			arguments:   []string{"path/to/trivy", "-v"},
			wantVersion: tableVersion,
		},
		{
			name:        "happy path. '-version' flag is used",
			arguments:   []string{"path/to/trivy", "-version"},
			wantVersion: tableVersion,
		},
		{
			name:        "happy path. 'version' command is used",
			arguments:   []string{"path/to/trivy", "version"},
			wantVersion: tableVersion,
		},
		{
			name:        "happy path. 'version', '--format json' flags are used",
			arguments:   []string{"path/to/trivy", "version", "--format", "json"},
			wantVersion: jsonVersion,
		},
		{
			name:      "sad path. '-v', '--format json' flags are used",
			arguments: []string{"path/to/trivy", "-v", "--format", "json"},
			wantError: "flag provided but not defined: -format",
		},
		{
			name:      "sad path. '-version', '--format json' flags are used",
			arguments: []string{"path/to/trivy", "-version", "--format", "json"},
			wantError: "flag provided but not defined: -format",
		},
	}

	savedShowVersion := showVersion
	defer func() { showVersion = savedShowVersion }()

	for _, test := range tests {

		t.Run(test.name, func(t *testing.T) {
			resultVersion := ""
			showVersion = func(cacheDir, outputFormat, version string, outputWriter io.Writer) {
				if outputFormat == "json" {
					resultVersion = jsonVersion
				} else {
					resultVersion = tableVersion
				}
			}
			t.Failed()
			app := NewApp("test")
			err := app.Run(test.arguments)

			if test.wantError != "" {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				assert.Equal(t, test.wantVersion, resultVersion)
			}
		})
	}
}

func TestNewCommands(t *testing.T) {
	NewApp("test")
	NewClientCommand()
	NewFilesystemCommand()
	NewImageCommand()
	NewRepositoryCommand()
	NewServerCommand()
}
