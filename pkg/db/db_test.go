package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	tdb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const mediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return mediaType, nil
}

func newFakeLayer(t *testing.T, input string) v1.Layer {
	layer, err := tarball.LayerFromFile(input)
	require.NoError(t, err)

	return fakeLayer{layer}
}

func TestClient_NeedsUpdate(t *testing.T) {
	timeNextUpdateDay1 := time.Date(2019, 9, 1, 0, 0, 0, 0, time.UTC)
	timeNextUpdateDay2 := time.Date(2019, 10, 2, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		skip     bool
		clock    clock.Clock
		metadata metadata.Metadata
		want     bool
		wantErr  string
	}{
		{
			name:  "happy path",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    tdb.SchemaVersion,
				NextUpdate: timeNextUpdateDay1,
			},
			want: true,
		},
		{
			name:     "happy path for first run",
			clock:    clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{},
			want:     true,
		},
		{
			name:  "happy path with old schema version",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    0,
				NextUpdate: timeNextUpdateDay1,
			},
			want: true,
		},
		{
			name:  "happy path with --skip-update",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    tdb.SchemaVersion,
				NextUpdate: timeNextUpdateDay1,
			},
			skip: true,
			want: false,
		},
		{
			name:  "skip downloading DB",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    tdb.SchemaVersion,
				NextUpdate: timeNextUpdateDay2,
			},
			want: false,
		},
		{
			name:  "newer schema version",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    tdb.SchemaVersion + 1,
				NextUpdate: timeNextUpdateDay2,
			},
			wantErr: fmt.Sprintf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
				tdb.SchemaVersion+1, tdb.SchemaVersion),
		},
		{
			name:     "--skip-update on the first run",
			clock:    clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{},
			skip:     true,
			wantErr:  "--skip-update cannot be specified on the first run",
		},
		{
			name:  "--skip-update with different schema version",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:    0,
				NextUpdate: timeNextUpdateDay1,
			},
			skip: true,
			wantErr: fmt.Sprintf("--skip-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
				0, tdb.SchemaVersion),
		},
		{
			name:  "happy with old DownloadedAt",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:      tdb.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 22, 30, 0, 0, time.UTC),
			},
			want: true,
		},
		{
			name:  "skip downloading DB with recent DownloadedAt",
			clock: clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC)),
			metadata: metadata.Metadata{
				Version:      tdb.SchemaVersion,
				NextUpdate:   timeNextUpdateDay1,
				DownloadedAt: time.Date(2019, 9, 30, 23, 30, 0, 0, time.UTC),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			if tt.metadata != (metadata.Metadata{}) {
				meta := metadata.NewClient(cacheDir)
				err := meta.Update(tt.metadata)
				require.NoError(t, err)
			}

			client := db.NewClient(cacheDir, true, db.WithClock(tt.clock))
			needsUpdate, err := client.NeedsUpdate("test", tt.skip)

			switch {
			case tt.wantErr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, needsUpdate)
		})
	}
}

func TestClient_Download(t *testing.T) {
	timeDownloadedAt := clocktesting.NewFakeClock(time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC))

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
			wantErr: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()

			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns([]v1.Layer{newFakeLayer(t, tt.input)}, nil)
			img.ManifestReturns(&v1.Manifest{
				Layers: []v1.Descriptor{
					{
						MediaType: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
						Size:      100,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "aec482bc254b5dd025d3eaf5bb35997d3dba783e394e8f91d5a415963151bfb8",
						},
						Annotations: map[string]string{
							"org.opencontainers.image.title": "db.tar.gz",
						},
					},
				},
			}, nil)

			// Mock OCI artifact
			opt := ftypes.RemoteOptions{
				Insecure: false,
			}
			art, err := oci.NewArtifact("db", true, opt, oci.WithImage(img))
			require.NoError(t, err)

			client := db.NewClient(cacheDir, true, db.WithOCIArtifact(art), db.WithClock(timeDownloadedAt))
			err = client.Download(context.Background(), cacheDir, opt)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			meta := metadata.NewClient(cacheDir)
			got, err := meta.Get()
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
