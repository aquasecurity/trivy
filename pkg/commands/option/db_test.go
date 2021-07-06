package option_test

import (
	"flag"
	"testing"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestNewDBOption(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want option.DBOption
	}{
		{
			name: "happy path",
			args: []string{"--reset", "--skip-db-update"},
			want: option.DBOption{
				Reset:        true,
				SkipDBUpdate: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.Bool("reset", false, "")
			set.Bool("skip-db-update", false, "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			got := option.NewDBOption(c)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestDBOption_Init(t *testing.T) {
	type fields struct {
		Reset          bool
		DownloadDBOnly bool
		SkipUpdate     bool
		Light          bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				Light: true,
			},
		},
		{
			name: "sad path",
			fields: fields{
				DownloadDBOnly: true,
				SkipUpdate:     true,
			},
			wantErr: "--skip-db-update and --download-db-only options can not be specified both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &option.DBOption{
				Reset:          tt.fields.Reset,
				DownloadDBOnly: tt.fields.DownloadDBOnly,
				SkipDBUpdate:   tt.fields.SkipUpdate,
				Light:          tt.fields.Light,
			}

			err := c.Init()
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
