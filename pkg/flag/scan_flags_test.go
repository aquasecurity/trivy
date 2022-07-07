package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanFlags_ToOptions(t *testing.T) {
	type fields struct {
		skipDirs       []string
		skipFiles      []string
		offlineScan    bool
		vulnType       string
		securityChecks string
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
			name: "happy path for OS vulnerabilities",
			args: []string{"alpine:latest"},
			fields: fields{
				vulnType:       "os",
				securityChecks: "vuln",
			},
			want: flag.ScanOptions{
				Target:         "alpine:latest",
				VulnType:       []string{types.VulnTypeOS},
				SecurityChecks: []string{types.SecurityCheckVulnerability},
			},
		},
		{
			name: "happy path for library vulnerabilities",
			args: []string{"alpine:latest"},
			fields: fields{
				vulnType:       "library",
				securityChecks: "vuln",
			},
			want: flag.ScanOptions{
				Target:         "alpine:latest",
				VulnType:       []string{types.VulnTypeLibrary},
				SecurityChecks: []string{types.SecurityCheckVulnerability},
			},
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
		},
		{
			name: "with wrong security check",
			fields: fields{
				securityChecks: "vuln,WRONG-CHECK",
			},
			want: flag.ScanOptions{
				SecurityChecks: []string{types.SecurityCheckVulnerability},
			},
			wantLogs: []string{
				`unknown security check: WRONG-CHECK`,
			},
		},
		{
			name: "with wrong vuln type",
			fields: fields{
				vulnType: "os,nonevuln",
			},
			want: flag.ScanOptions{
				VulnType: []string{types.VulnTypeOS},
			},
			wantLogs: []string{
				`unknown vulnerability type: nonevuln`,
			},
		},
		{
			name:   "without target (args)",
			args:   []string{},
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

			viper.Set(flag.SkipDirsFlag, tt.fields.skipDirs)
			viper.Set(flag.SkipFilesFlag, tt.fields.skipFiles)
			viper.Set(flag.OfflineScanFlag, tt.fields.offlineScan)
			viper.Set(flag.VulnTypeFlag, tt.fields.vulnType)
			viper.Set(flag.SecurityChecksFlag, tt.fields.securityChecks)

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
