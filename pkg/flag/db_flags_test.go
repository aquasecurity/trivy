package flag_test

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestDBFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		SkipDBUpdate     bool
		DownloadDBOnly   bool
		Light            bool
		DBRepository     []string
		JavaDBRepository []string
	}
	tests := []struct {
		name     string
		fields   fields
		want     flag.DBOptions
		wantLogs []string
		wantErr  string
	}{
		{
			name: "happy",
			fields: fields{
				SkipDBUpdate:     true,
				DownloadDBOnly:   false,
				DBRepository:     []string{"ghcr.io/aquasecurity/trivy-db"},
				JavaDBRepository: []string{"ghcr.io/aquasecurity/trivy-java-db"},
			},
			want: flag.DBOptions{
				SkipDBUpdate:       true,
				DownloadDBOnly:     false,
				DBRepositories:     []name.Reference{name.Tag{}}, // All fields are unexported
				JavaDBRepositories: []name.Reference{name.Tag{}}, // All fields are unexported
			},
			wantLogs: []string{
				`Adding schema version to the DB repository for backward compatibility	repository="ghcr.io/aquasecurity/trivy-db:2"`,
				`Adding schema version to the DB repository for backward compatibility	repository="ghcr.io/aquasecurity/trivy-java-db:1"`,
			},
		},
		{
			name: "sad",
			fields: fields{
				SkipDBUpdate:   true,
				DownloadDBOnly: true,
			},
			wantErr: "--skip-db-update and --download-db-only options can not be specified both",
		},
		{
			name: "invalid repo",
			fields: fields{
				SkipDBUpdate:   true,
				DownloadDBOnly: false,
				DBRepository:   []string{"foo:bar:baz"},
			},
			wantErr: "invalid DB repository",
		},
		{
			name: "multiple repos",
			fields: fields{
				SkipDBUpdate:   true,
				DownloadDBOnly: false,
				DBRepository: []string{
					"mirror.gcr.io/aquasec/trivy-db:2",
					"ghcr.io/aquasecurity/trivy-db:2",
				},
				JavaDBRepository: []string{
					"mirror.gcr.io/aquasec/trivy-java-db:1",
					"ghcr.io/aquasecurity/trivy-java-db:1",
				},
			},
			want: flag.DBOptions{
				SkipDBUpdate:       true,
				DownloadDBOnly:     false,
				DBRepositories:     []name.Reference{name.Tag{}, name.Tag{}}, // All fields are unexported
				JavaDBRepositories: []name.Reference{name.Tag{}, name.Tag{}}, // All fields are unexported
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := newLogger(log.LevelInfo)

			viper.Set(flag.SkipDBUpdateFlag.ConfigName, tt.fields.SkipDBUpdate)
			viper.Set(flag.DownloadDBOnlyFlag.ConfigName, tt.fields.DownloadDBOnly)
			viper.Set(flag.DBRepositoryFlag.ConfigName, tt.fields.DBRepository)
			viper.Set(flag.JavaDBRepositoryFlag.ConfigName, tt.fields.JavaDBRepository)

			// Assert options
			f := &flag.DBFlagGroup{
				DownloadDBOnly:     flag.DownloadDBOnlyFlag.Clone(),
				SkipDBUpdate:       flag.SkipDBUpdateFlag.Clone(),
				DBRepositories:     flag.DBRepositoryFlag.Clone(),
				JavaDBRepositories: flag.JavaDBRepositoryFlag.Clone(),
			}
			got, err := f.ToOptions()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.EqualExportedValues(t, tt.want, got)

			// Assert log messages
			assert.Equal(t, tt.wantLogs, out.Messages(), tt.name)
		})
	}
}
