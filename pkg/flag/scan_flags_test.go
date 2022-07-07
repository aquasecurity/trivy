package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestScanFlags_ToOptions(t *testing.T) {
	type fields struct {
		SkipDirs       []string
		SkipFiles      []string
		OfflineScan    bool
		VulnType       string
		SecurityChecks string
	}
	tests := []struct {
		name     string
		args     []string
		fields   fields
		want     flag.ScanOptions
		wantLogs []string
	}{
		{
			name:   "happy path",
			args:   []string{"alpine:latest"},
			fields: fields{},
			want: flag.ScanOptions{
				Target: "alpine:latest",
			},
		},
		{
			name:   "without target (args)",
			args:   []string{"alpine:latest"},
			fields: fields{},
			want:   flag.ScanOptions{},
		},
		{
			name:   "with two or more targets (args)",
			args:   []string{"alpine:latest", "nginx:latest"},
			fields: fields{},
			want:   flag.ScanOptions{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := zap.WarnLevel

			core, obs := observer.New(level)
			log.Logger = zap.New(core).Sugar()

			viper.Set(flag.SkipDirsFlag, tt.fields.SkipDirs)
			viper.Set(flag.SkipFilesFlag, tt.fields.SkipFiles)
			viper.Set(flag.OfflineScanFlag, tt.fields.OfflineScan)
			viper.Set(flag.VulnTypeFlag, tt.fields.VulnType)
			viper.Set(flag.SecurityChecksFlag, tt.fields.SecurityChecks)

			// Assert options
			f := &flag.ScanFlags{}

			got, err := f.ToOptions(tt.args)
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")

			// Assert log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.wantLogs, gotMessages, tt.name)
		})

	}
}
