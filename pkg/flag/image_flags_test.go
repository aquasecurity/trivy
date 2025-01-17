package flag_test

import (
	"testing"

	"github.com/docker/go-units"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestImageFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		maxImgSize string
		platform   string
	}
	tests := []struct {
		name    string
		fields  fields
		want    flag.ImageOptions
		wantErr string
	}{
		{
			name:   "happy default (without flags)",
			fields: fields{},
			want:   flag.ImageOptions{},
		},
		{
			name: "happy path with max image size",
			fields: fields{
				maxImgSize: "10mb",
			},
			want: flag.ImageOptions{
				MaxImageSize: units.MB * 10,
			},
		},
		{
			name: "invalid max image size",
			fields: fields{
				maxImgSize: "10foo",
			},
			wantErr: "invalid max image size",
		},
		{
			name: "happy path with platform",
			fields: fields{
				platform: "linux/amd64",
			},
			want: flag.ImageOptions{
				Platform: types.Platform{
					Platform: &v1.Platform{
						OS:           "linux",
						Architecture: "amd64",
					},
				},
			},
		},
		{
			name: "invalid platform",
			fields: fields{
				platform: "unknown/unknown/unknown/unknown",
			},
			wantErr: "unable to parse platform",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			setValue(flag.MaxImageSize.ConfigName, tt.fields.maxImgSize)
			setValue(flag.PlatformFlag.ConfigName, tt.fields.platform)

			f := &flag.ImageFlagGroup{
				MaxImageSize: flag.MaxImageSize.Clone(),
				Platform:     flag.PlatformFlag.Clone(),
			}

			got, err := f.ToOptions()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.EqualExportedValues(t, tt.want, got)
		})
	}
}
