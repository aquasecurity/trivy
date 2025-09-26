package db_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestClient_NeedsUpdate(t *testing.T) {
	timeNextUpdateDay1 := time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC)
	timeNextUpdateDay2 := time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC)

	timeDownloadAt := time.Date(2019, 9, 30, 22, 30, 0, 0, time.UTC)

	tests := []struct {
		name         string
		skip         bool
		dbFileExists bool
		metadata     metadata.Metadata
		want         bool
		wantLogs     []string
		wantErr      string
	}{
		{
			name:         "happy path",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: timeDownloadAt,
			},
			want: true,
		},
		{
			name:         "happy path for first run",
			dbFileExists: true,
			metadata:     metadata.Metadata{},
			want:         true,
			wantLogs: []string{
				"There is no valid metadata file",
			},
		},
		{
			name:         "happy path for first run without trivy.db",
			dbFileExists: false,
			want:         true,
			wantLogs: []string{
				"There is no db file",
				"There is no valid metadata file",
			},
		},
		{
			name:         "happy path with old schema version",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      0,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: timeDownloadAt,
			},
			want: true,
			wantLogs: []string{
				"The local DB schema version does not match with supported version schema.",
			},
		},
		{
			name:         "happy path with --skip-db-update",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: timeDownloadAt,
			},
			skip: true,
			want: false,
			wantLogs: []string{
				"Skipping DB update...",
			},
		},
		{
			name:         "skip downloading DB",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay2,
				DownloadedAt: timeDownloadAt,
			},
			want: false,
			wantLogs: []string{
				"DB update was skipped because the local DB is the latest",
			},
		},
		{
			name:         "newer schema version",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion + 1,
				NextUpdate:   timeNextUpdateDay2,
				DownloadedAt: timeDownloadAt,
			},
			wantErr: fmt.Sprintf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
				db.SchemaVersion+1, db.SchemaVersion),
			wantLogs: []string{
				"Trivy version is old. Update to the latest version.",
			},
		},
		{
			name:         "--skip-db-update without trivy.db on the first run",
			dbFileExists: false,
			skip:         true,
			wantErr:      "--skip-db-update cannot be specified on the first run",
			wantLogs: []string{
				"There is no db file",
				"There is no valid metadata file",
				"The first run cannot skip downloading DB",
			},
		},
		{
			name:         "--skip-db-update without metadata.json on the first run",
			dbFileExists: true,
			metadata:     metadata.Metadata{},
			skip:         true,
			wantErr:      "--skip-db-update cannot be specified on the first run",
			wantLogs: []string{
				"There is no valid metadata file",
				"The first run cannot skip downloading DB",
			},
		},
		{
			name:         "--skip-db-update with different schema version",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      0,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: timeDownloadAt,
			},
			skip: true,
			wantErr: fmt.Sprintf("--skip-db-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
				0, db.SchemaVersion),
			wantLogs: []string{
				"The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.",
			},
		},
		{
			name:         "happy with old DownloadedAt",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: timeDownloadAt,
			},
			want: true,
		},
		{
			name:         "skip downloading DB with recent DownloadedAt",
			dbFileExists: true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 23, 30, 0, 0, time.UTC),
			},
			want: false,
			wantLogs: []string{
				"DB update was skipped because the local DB was downloaded during the last hour",
			},
		},
		{
			name:         "DownloadedAt is zero, skip is false",
			dbFileExists: true,
			skip:         false,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				DownloadedAt: time.Time{}, // zero time
				NextUpdate:   timeNextUpdateDay1,
			},
			want: true,
			wantLogs: []string{
				"Trivy DB may be corrupted and will be re-downloaded. If you manually downloaded DB - use the `--skip-db-update` flag to skip updating DB.",
			},
		},
		{
			name:         "DownloadedAt is zero, skip is true",
			dbFileExists: true,
			skip:         true,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				DownloadedAt: time.Time{}, // zero time
				NextUpdate:   timeNextUpdateDay1,
			},
			want: false,
			wantLogs: []string{
				"Skipping DB update...",
			},
		},
		{
			name:         "DownloadedAt is zero, skip is true, old schema version",
			dbFileExists: true,
			skip:         true,
			metadata: metadata.Metadata{
				Version:      0,
				DownloadedAt: time.Time{}, // zero time
				NextUpdate:   timeNextUpdateDay1,
			},
			wantErr: "--skip-db-update cannot be specified with the old DB schema. Local DB: 0, Expected: 2",
			want:    false,
			wantLogs: []string{
				"The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.",
			},
		},
		{
			name:         "trivy.db is missing but metadata with recent DownloadedAt",
			dbFileExists: false,
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 23, 30, 0, 0, time.UTC),
			},
			want: true,
			wantLogs: []string{
				"There is no db file",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := bytes.NewBuffer(nil)
			logger := log.New(log.NewHandler(out, &log.Options{Level: log.LevelDebug}))
			log.SetDefault(logger)

			dbDir := db.Dir(t.TempDir())
			if tt.metadata != (metadata.Metadata{}) {
				meta := metadata.NewClient(dbDir)
				err := meta.Update(tt.metadata)
				require.NoError(t, err)
			}

			if tt.dbFileExists {
				err := db.Init(dbDir)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, db.Close())
				})
			}

			// Set a fake time
			ctx := clock.With(t.Context(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

			client := db.NewClient(dbDir, true)
			needsUpdate, err := client.NeedsUpdate(ctx, "test", tt.skip)

			// Compare log messages
			require.Len(t, lo.Compact(strings.Split(out.String(), "\n")), len(tt.wantLogs))
			for _, logMsg := range tt.wantLogs {
				assert.Contains(t, out.String(), logMsg)
			}

			switch {
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr, tt.name)
			default:
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, needsUpdate)
		})
	}
}

func TestClient_Download(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    metadata.Metadata
		wantErr string
	}{
		{
			name:  "happy path",
			input: "testdata/db.tar.gz",
			want: metadata.Metadata{
				Version:      1,
				NextUpdate:   time.Date(3000, 1, 1, 18, 5, 43, 198355188, time.UTC),
				UpdatedAt:    time.Date(3000, 1, 1, 12, 5, 43, 198355588, time.UTC),
				DownloadedAt: time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:    "invalid gzip",
			input:   "testdata/trivy.db",
			wantErr: "OCI artifact error: failed to download vulnerability DB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set a fake time
			ctx := clock.With(t.Context(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

			// Fake DB
			art := dbtest.NewFakeDB(t, tt.input, dbtest.FakeDBOptions{})

			dbDir := db.Dir(t.TempDir())
			client := db.NewClient(dbDir, true, db.WithOCIArtifact(art))
			err := client.Download(ctx, dbDir, ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			meta := metadata.NewClient(dbDir)
			got, err := meta.Get()
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
