package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestClient_NeedsUpdate(t *testing.T) {
	timeNextUpdateDay1 := time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC)
	timeNextUpdateDay2 := time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		skip     bool
		metadata metadata.Metadata
		want     bool
		wantErr  string
	}{
		{
			name: "happy path",
			metadata: metadata.Metadata{
				Version:    db.SchemaVersion,
				NextUpdate: timeNextUpdateDay1,
			},
			want: true,
		},
		{
			name:     "happy path for first run",
			metadata: metadata.Metadata{},
			want:     true,
		},
		{
			name: "happy path with old schema version",
			metadata: metadata.Metadata{
				Version:    0,
				NextUpdate: timeNextUpdateDay1,
			},
			want: true,
		},
		{
			name: "happy path with --skip-update",
			metadata: metadata.Metadata{
				Version:    db.SchemaVersion,
				NextUpdate: timeNextUpdateDay1,
			},
			skip: true,
			want: false,
		},
		{
			name: "skip downloading DB",
			metadata: metadata.Metadata{
				Version:    db.SchemaVersion,
				NextUpdate: timeNextUpdateDay2,
			},
			want: false,
		},
		{
			name: "newer schema version",
			metadata: metadata.Metadata{
				Version:    db.SchemaVersion + 1,
				NextUpdate: timeNextUpdateDay2,
			},
			wantErr: fmt.Sprintf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
				db.SchemaVersion+1, db.SchemaVersion),
		},
		{
			name:     "--skip-update on the first run",
			metadata: metadata.Metadata{},
			skip:     true,
			wantErr:  "--skip-update cannot be specified on the first run",
		},
		{
			name: "--skip-update with different schema version",
			metadata: metadata.Metadata{
				Version:    0,
				NextUpdate: timeNextUpdateDay1,
			},
			skip: true,
			wantErr: fmt.Sprintf("--skip-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
				0, db.SchemaVersion),
		},
		{
			name: "happy with old DownloadedAt",
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 22, 30, 0, 0, time.UTC),
			},
			want: true,
		},
		{
			name: "skip downloading DB with recent DownloadedAt",
			metadata: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 23, 30, 0, 0, time.UTC),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbDir := db.Dir(t.TempDir())
			if tt.metadata != (metadata.Metadata{}) {
				meta := metadata.NewClient(dbDir)
				err := meta.Update(tt.metadata)
				require.NoError(t, err)
			}

			// Set a fake time
			ctx := clock.With(context.Background(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

			client := db.NewClient(dbDir, true)
			needsUpdate, err := client.NeedsUpdate(ctx, "test", tt.skip)

			switch {
			case tt.wantErr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
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
			ctx := clock.With(context.Background(), time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

			// Fake DB
			art := dbtest.NewFakeDB(t, tt.input, dbtest.FakeDBOptions{})

			dbDir := db.Dir(t.TempDir())
			client := db.NewClient(dbDir, true, db.WithOCIArtifact(art))
			err := client.Download(ctx, dbDir, ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				require.Error(t, err)
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
