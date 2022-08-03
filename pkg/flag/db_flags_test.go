package flag_test

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestDBFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		SkipDBUpdate   bool
		DownloadDBOnly bool
		Light          bool
	}
	tests := []struct {
		name      string
		fields    fields
		want      flag.DBOptions
		wantLogs  []string
		assertion require.ErrorAssertionFunc
	}{
		{
			name: "happy",
			fields: fields{
				SkipDBUpdate:   true,
				DownloadDBOnly: false,
			},
			want: flag.DBOptions{
				SkipDBUpdate:   true,
				DownloadDBOnly: false,
			},
			assertion: require.NoError,
		},
		{
			name: "light",
			fields: fields{
				Light: true,
			},
			want: flag.DBOptions{
				Light: true,
			},
			wantLogs: []string{
				"'--light' option is deprecated and will be removed. See also: https://github.com/aquasecurity/trivy/discussions/1649",
			},
			assertion: require.NoError,
		},
		{
			name: "sad",
			fields: fields{
				SkipDBUpdate:   true,
				DownloadDBOnly: true,
			},
			assertion: func(t require.TestingT, err error, msgs ...interface{}) {
				require.ErrorContains(t, err, "--skip-db-update and --download-db-only options can not be specified both")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := zap.WarnLevel
			core, obs := observer.New(level)
			log.Logger = zap.New(core).Sugar()

			viper.Set(flag.SkipDBUpdateFlag.ConfigName, tt.fields.SkipDBUpdate)
			viper.Set(flag.DownloadDBOnlyFlag.ConfigName, tt.fields.DownloadDBOnly)
			viper.Set(flag.LightFlag.ConfigName, tt.fields.Light)

			// Assert options
			f := &flag.DBFlagGroup{
				DownloadDBOnly: &flag.DownloadDBOnlyFlag,
				SkipDBUpdate:   &flag.SkipDBUpdateFlag,
				Light:          &flag.LightFlag,
			}
			got, err := f.ToOptions()
			tt.assertion(t, err)
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
