package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/version"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

func Test_dbWorker_update(t *testing.T) {
	cachedMetadata := metadata.Metadata{
		Version:      db.SchemaVersion,
		NextUpdate:   time.Date(2020, 10, 2, 0, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC),
		DownloadedAt: time.Date(2020, 10, 1, 1, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		name           string
		now            time.Time
		skipUpdate     bool
		layerMediaType types.MediaType
		want           metadata.Metadata
		wantErr        string
	}{
		{
			name:       "update needed",
			now:        time.Date(2021, 10, 1, 0, 0, 0, 0, time.UTC),
			skipUpdate: false,
			want: metadata.Metadata{
				Version:      db.SchemaVersion,
				NextUpdate:   time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:    time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
				DownloadedAt: time.Date(2021, 10, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:       "not update needed",
			now:        time.Date(2019, 10, 1, 0, 0, 0, 0, time.UTC),
			skipUpdate: false,
			want:       cachedMetadata,
		},
		{
			name:       "skip update",
			now:        time.Date(2021, 10, 1, 0, 0, 0, 0, time.UTC),
			skipUpdate: true,
			want:       cachedMetadata,
		},
		{
			name:           "Download returns an error",
			now:            time.Date(2021, 10, 1, 0, 0, 0, 0, time.UTC),
			skipUpdate:     false,
			layerMediaType: types.MediaType("unknown"),
			wantErr:        "failed DB hot update",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbDir := db.Dir(t.TempDir())

			// Initialize the cache
			meta := metadata.NewClient(dbDir)
			err := meta.Update(cachedMetadata)
			require.NoError(t, err)

			err = db.Init(dbDir)
			require.NoError(t, err)

			defer func() { _ = db.Close() }()

			// Set a fake time
			ctx := clock.With(context.Background(), tt.now)

			// Set a fake DB
			dbPath := dbtest.ArchiveDir(t, "testdata/newdb")
			art := dbtest.NewFakeDB(t, dbPath, dbtest.FakeDBOptions{
				MediaType: tt.layerMediaType,
			})
			client := db.NewClient(dbDir, true, db.WithOCIArtifact(art))
			w := newDBWorker(client)

			var dbUpdateWg, requestWg sync.WaitGroup
			err = w.update(ctx, "1.2.3", dbDir,
				tt.skipUpdate, &dbUpdateWg, &requestWg, ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				require.Error(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err, tt.name)

			mc := metadata.NewClient(dbDir)
			got, err := mc.Get()
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestServer_newServeMux(t *testing.T) {
	type args struct {
		token       string
		tokenHeader string
	}
	tests := []struct {
		name   string
		args   args
		path   string
		header http.Header
		want   int
	}{
		{
			name: "health check",
			path: "/healthz",
			want: http.StatusOK,
		},
		{
			name: "cache endpoint",
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "with token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Authorization": []string{"test"},
				"Content-Type":  []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "sad path: no handler",
			path: "/sad",
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusNotFound,
		},
		{
			name: "sad path: invalid token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbUpdateWg, requestWg := &sync.WaitGroup{}, &sync.WaitGroup{}

			c, err := cache.NewFSCache(t.TempDir())
			require.NoError(t, err)
			defer func() { _ = c.Close() }()

			s := NewServer("", "", "", tt.args.token, tt.args.tokenHeader, "", nil, ftypes.RegistryOptions{})
			ts := httptest.NewServer(s.NewServeMux(context.Background(), c, dbUpdateWg, requestWg))
			defer ts.Close()

			var resp *http.Response
			url := ts.URL + tt.path
			if tt.header == nil {
				resp, err = http.Get(url)
				require.NoError(t, err)
				defer resp.Body.Close()
			} else {
				req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
				require.NoError(t, err)

				req.Header = tt.header
				client := new(http.Client)
				resp, err = client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
			}
			assert.Equal(t, tt.want, resp.StatusCode)
		})
	}
}

func Test_VersionEndpoint(t *testing.T) {
	dbUpdateWg, requestWg := &sync.WaitGroup{}, &sync.WaitGroup{}
	c, err := cache.NewFSCache(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	s := NewServer("", "", "testdata/testcache", "", "", "", nil, ftypes.RegistryOptions{})
	ts := httptest.NewServer(s.NewServeMux(context.Background(), c, dbUpdateWg, requestWg))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/version")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var versionInfo version.VersionInfo
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&versionInfo))

	expected := version.VersionInfo{
		Version: "dev",
		VulnerabilityDB: &metadata.Metadata{
			Version:      2,
			NextUpdate:   time.Date(2023, 7, 20, 18, 11, 37, 696263532, time.UTC),
			UpdatedAt:    time.Date(2023, 7, 20, 12, 11, 37, 696263932, time.UTC),
			DownloadedAt: time.Date(2023, 7, 25, 7, 1, 41, 239158000, time.UTC),
		},
		CheckBundle: &policy.Metadata{
			Digest:       "sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43",
			DownloadedAt: time.Date(2023, 7, 23, 16, 40, 33, 122462000, time.UTC),
		},
	}
	assert.Equal(t, expected, versionInfo)
}
