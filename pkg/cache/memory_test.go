package cache_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestMemoryCache_PutArtifact(t *testing.T) {
	tests := []struct {
		name         string
		artifactID   string
		artifactInfo types.ArtifactInfo
	}{
		{
			name:       "happy path",
			artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			artifactInfo: types.ArtifactInfo{
				SchemaVersion: 2,
				Architecture:  "amd64",
				Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
				DockerVersion: "19.03.12",
				OS:            "linux",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			err := c.PutArtifact(tt.artifactID, tt.artifactInfo)
			require.NoError(t, err)

			got, err := c.GetArtifact(tt.artifactID)
			require.NoError(t, err)
			assert.Equal(t, tt.artifactInfo, got)
		})
	}
}

func TestMemoryCache_PutBlob(t *testing.T) {
	tests := []struct {
		name     string
		blobID   string
		blobInfo types.BlobInfo
	}{
		{
			name:   "happy path",
			blobID: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			blobInfo: types.BlobInfo{
				SchemaVersion: 2,
				Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
				DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				OS: types.OS{
					Family: "alpine",
					Name:   "3.10.2",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "lib/apk/db/installed",
						Packages: []types.Package{
							{
								Name:       "musl",
								Version:    "1.1.22-r3",
								SrcName:    "musl",
								SrcVersion: "1.1.22-r3",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			err := c.PutBlob(tt.blobID, tt.blobInfo)
			require.NoError(t, err)

			got, err := c.GetBlob(tt.blobID)
			require.NoError(t, err)
			assert.Equal(t, tt.blobInfo, got)
		})
	}
}

func TestMemoryCache_GetArtifact(t *testing.T) {
	tests := []struct {
		name         string
		artifactID   string
		artifactInfo types.ArtifactInfo
		wantErr      bool
	}{
		{
			name:       "happy path",
			artifactID: "sha256:8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf",
			artifactInfo: types.ArtifactInfo{
				SchemaVersion: 2,
				Architecture:  "amd64",
				Created:       time.Date(2020, 11, 14, 0, 20, 4, 0, time.UTC),
				DockerVersion: "19.03.12",
				OS:            "linux",
			},
			wantErr: false,
		},
		{
			name:       "not found",
			artifactID: "sha256:nonexistent",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			if !tt.wantErr {
				err := c.PutArtifact(tt.artifactID, tt.artifactInfo)
				require.NoError(t, err)
			}

			got, err := c.GetArtifact(tt.artifactID)
			if tt.wantErr {
				require.ErrorContains(t, err, "not found in memory cache")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.artifactInfo, got)
		})
	}
}

func TestMemoryCache_GetBlob(t *testing.T) {
	tests := []struct {
		name     string
		blobID   string
		blobInfo types.BlobInfo
		wantErr  bool
	}{
		{
			name:   "happy path",
			blobID: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			blobInfo: types.BlobInfo{
				SchemaVersion: 2,
				Digest:        "sha256:9d48c3bd43c520dc2784e868a780e976b207cbf493eaff8c6596eb871cbd9609",
				DiffID:        "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
				OS: types.OS{
					Family: "alpine",
					Name:   "3.10.2",
				},
			},
			wantErr: false,
		},
		{
			name:    "not found",
			blobID:  "sha256:nonexistent",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			if !tt.wantErr {
				err := c.PutBlob(tt.blobID, tt.blobInfo)
				require.NoError(t, err)
			}

			got, err := c.GetBlob(tt.blobID)
			if tt.wantErr {
				require.ErrorContains(t, err, "not found in memory cache")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.blobInfo, got)
		})
	}
}

func TestMemoryCache_MissingBlobs(t *testing.T) {
	tests := []struct {
		name                string
		artifactID          string
		blobIDs             []string
		putArtifact         bool
		putBlobs            []string
		wantMissingArtifact bool
		wantMissingBlobIDs  []string
	}{
		{
			name:       "missing both artifact and blob",
			artifactID: "sha256:artifact1",
			blobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			putArtifact:         false,
			putBlobs:            []string{},
			wantMissingArtifact: true,
			wantMissingBlobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
		},
		{
			name:       "missing artifact only",
			artifactID: "sha256:artifact1",
			blobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			putArtifact: false,
			putBlobs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			wantMissingArtifact: true,
			wantMissingBlobIDs:  nil,
		},
		{
			name:       "missing one blob",
			artifactID: "sha256:artifact1",
			blobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			putArtifact:         true,
			putBlobs:            []string{"sha256:blob1"},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  []string{"sha256:blob2"},
		},
		{
			name:       "no missing blobs",
			artifactID: "sha256:artifact1",
			blobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			putArtifact: true,
			putBlobs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
			wantMissingArtifact: false,
			wantMissingBlobIDs:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			if tt.putArtifact {
				err := c.PutArtifact(tt.artifactID, types.ArtifactInfo{})
				require.NoError(t, err)
			}

			for _, blobID := range tt.putBlobs {
				err := c.PutBlob(blobID, types.BlobInfo{})
				require.NoError(t, err)
			}

			gotMissingArtifact, gotMissingBlobIDs, err := c.MissingBlobs(tt.artifactID, tt.blobIDs)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMissingArtifact, gotMissingArtifact)
			assert.Equal(t, tt.wantMissingBlobIDs, gotMissingBlobIDs)
		})
	}
}

func TestMemoryCache_DeleteBlobs(t *testing.T) {
	tests := []struct {
		name    string
		blobIDs []string
	}{
		{
			name: "delete existing blobs",
			blobIDs: []string{
				"sha256:blob1",
				"sha256:blob2",
			},
		},
		{
			name: "delete non-existing blobs",
			blobIDs: []string{
				"sha256:nonexistent1",
				"sha256:nonexistent2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			// Put some blobs in the cache
			for _, blobID := range tt.blobIDs {
				err := c.PutBlob(blobID, types.BlobInfo{})
				require.NoError(t, err)
			}

			err := c.DeleteBlobs(tt.blobIDs)
			require.NoError(t, err)

			// Check that the blobs are no longer in the cache
			for _, blobID := range tt.blobIDs {
				_, err := c.GetBlob(blobID)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not found in memory cache")
			}
		})
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		blobID     string
	}{
		{
			name:       "clear cache",
			artifactID: "sha256:artifact1",
			blobID:     "sha256:blob1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			err := c.PutArtifact(tt.artifactID, types.ArtifactInfo{})
			require.NoError(t, err)

			err = c.PutBlob(tt.blobID, types.BlobInfo{})
			require.NoError(t, err)

			err = c.Clear()
			require.NoError(t, err)

			_, err = c.GetArtifact(tt.artifactID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found in memory cache")

			_, err = c.GetBlob(tt.blobID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found in memory cache")
		})
	}
}

func TestMemoryCache_Close(t *testing.T) {
	tests := []struct {
		name       string
		artifactID string
		blobID     string
	}{
		{
			name:       "close cache",
			artifactID: "sha256:artifact1",
			blobID:     "sha256:blob1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cache.NewMemoryCache()

			err := c.PutArtifact(tt.artifactID, types.ArtifactInfo{})
			require.NoError(t, err)

			err = c.PutBlob(tt.blobID, types.BlobInfo{})
			require.NoError(t, err)

			err = c.Close()
			require.NoError(t, err)

			_, err = c.GetArtifact(tt.artifactID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found in memory cache")

			_, err = c.GetBlob(tt.blobID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found in memory cache")
		})
	}
}
