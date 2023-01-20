package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		skipDirs       []string
		skipFiles      []string
		onlyDirs       []string
		offlineScan    bool
		securityChecks string
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
				securityChecks: "config",
			},
			want: flag.ScanOptions{
				Target:         "alpine:latest",
				SecurityChecks: []string{types.SecurityCheckConfig},
			},
			assertion: require.NoError,
		},
		{
			name: "with wrong security check",
			fields: fields{
				securityChecks: "vuln,WRONG-CHECK",
			},
			want: flag.ScanOptions{},
			assertion: func(t require.TestingT, err error, msgs ...interface{}) {
				require.ErrorContains(t, err, "unknown security check: WRONG-CHECK")
			},
		},
		{
			name:      "without target (args)",
			args:      []string{},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name:      "with two or more targets (args)",
			args:      []string{"alpine:latest", "nginx:latest"},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "skip two files",
			fields: fields{
				skipFiles: []string{"file1", "file2"},
			},
			want: flag.ScanOptions{
				SkipFiles: []string{"file1", "file2"},
			},
			assertion: require.NoError,
		},
		{
			name: "skip two folders",
			fields: fields{
				skipDirs: []string{"dir1", "dir2"},
			},
			want: flag.ScanOptions{
				SkipDirs: []string{"dir1", "dir2"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Set(flag.SkipDirsFlag.ConfigName, tt.fields.skipDirs)
			viper.Set(flag.SkipFilesFlag.ConfigName, tt.fields.skipFiles)
			viper.Set(flag.OnlyDirsFlag.ConfigName, tt.fields.onlyDirs)
			viper.Set(flag.OfflineScanFlag.ConfigName, tt.fields.offlineScan)
			viper.Set(flag.SecurityChecksFlag.ConfigName, tt.fields.securityChecks)

			// Assert options
			f := &flag.ScanFlagGroup{
				SkipDirs:       &flag.SkipDirsFlag,
				SkipFiles:      &flag.SkipFilesFlag,
				OnlyDirs:       &flag.OnlyDirsFlag,
				OfflineScan:    &flag.OfflineScanFlag,
				SecurityChecks: &flag.SecurityChecksFlag,
			}

			got, err := f.ToOptions(tt.args)
			tt.assertion(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")
		})

	}
}
