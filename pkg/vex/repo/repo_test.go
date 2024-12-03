package repo_test

import (
	"archive/zip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

var manifest = repo.Manifest{
	Name:        "test-repo",
	Description: "test repository",
	Versions: []repo.Version{
		{
			SpecVersion: "0.1",
			Locations: []repo.Location{
				{
					URL: "https://localhost",
				},
			},
			UpdateInterval: repo.Duration{Duration: time.Hour * 24},
		},
	},
}

func TestRepository_Manifest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/vex-repository.json" {
			err := json.NewEncoder(w).Encode(manifest)
			assert.NoError(t, err)
		}
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	tests := []struct {
		name    string
		setup   func(*testing.T, string, *repo.Repository)
		want    repo.Manifest
		wantErr string
	}{
		{
			name: "local manifest exists",
			setup: func(t *testing.T, dir string, _ *repo.Repository) {
				manifestFile := filepath.Join(dir, "vex", "repositories", "test-repo", "vex-repository.json")
				testutil.MustWriteJSON(t, manifestFile, manifest)
			},
			want: manifest,
		},
		{
			name: "fetch from remote",
			setup: func(t *testing.T, dir string, r *repo.Repository) {
				r.URL = ts.URL
			},
			want: manifest,
		},
		{
			name: "http error",
			setup: func(t *testing.T, dir string, r *repo.Repository) {
				r.URL = ts.URL + "/error"
			},
			wantErr: "failed to download the repository metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, m := setupManager(t)
			conf, err := m.Config(context.Background())
			require.NoError(t, err)

			r := conf.Repositories[0]
			tt.setup(t, tempDir, &r)

			got, err := r.Manifest(context.Background(), repo.Options{})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRepository_Index(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, string, *repo.Repository)
		want    repo.Index
		wantErr string
	}{
		{
			name: "local index exists",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				indexData := repo.RawIndex{
					UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					Packages: []repo.PackageEntry{
						{
							ID:       "pkg1",
							Location: "location1",
							Format:   "format1",
						},
						{
							ID:       "pkg2",
							Location: "location2",
							Format:   "format2",
						},
					},
				}

				indexPath := filepath.Join(cacheDir, "vex", "repositories", r.Name, "0.1", "index.json")
				testutil.MustWriteJSON(t, indexPath, indexData)
			},
			want: repo.Index{
				UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				Packages: map[string]repo.PackageEntry{
					"pkg1": {
						ID:       "pkg1",
						Location: "location1",
						Format:   "format1",
					},
					"pkg2": {
						ID:       "pkg2",
						Location: "location2",
						Format:   "format2",
					},
				},
			},
		},
		{
			name:    "index file not found",
			setup:   func(*testing.T, string, *repo.Repository) {},
			wantErr: "failed to open the file",
		},
		{
			name: "invalid JSON in index file",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				indexPath := filepath.Join(cacheDir, "vex", "repositories", r.Name, "0.1", "index.json")
				testutil.MustWriteFile(t, indexPath, []byte("invalid JSON"))
			},
			wantErr: "failed to decode the index",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, m := setupManager(t)
			conf, err := m.Config(context.Background())
			require.NoError(t, err)

			r := conf.Repositories[0]
			tt.setup(t, tempDir, &r)

			got, err := r.Index(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			tt.want.Path = filepath.Join(tempDir, "vex", "repositories", r.Name, "0.1", "index.json")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRepository_Update(t *testing.T) {
	ts := setUpRepository(t)
	defer ts.Close()

	tests := []struct {
		name      string
		setup     func(*testing.T, string, *repo.Repository)
		clockTime time.Time
		wantErr   string
		wantCache repo.CacheMetadata
	}{
		{
			name: "successful update",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, ts.URL+"/archive.zip")
			},
			clockTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			wantCache: repo.CacheMetadata{
				UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ETags:     map[string]string{ts.URL + "/archive.zip": "new-etag"},
			},
		},
		{
			name: "no update needed (within update interval)",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, "") // No location as the test server is not used

				repoDir := filepath.Join(cacheDir, "vex", "repositories", r.Name)
				testutil.MustMkdirAll(t, filepath.Join(repoDir, "0.1"))

				cacheMetadata := repo.CacheMetadata{
					UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					ETags:     map[string]string{ts.URL + "/archive.zip": "current-etag"},
				}
				testutil.MustWriteJSON(t, filepath.Join(repoDir, "cache.json"), cacheMetadata)
			},
			clockTime: time.Date(2023, 1, 1, 1, 30, 0, 0, time.UTC),
			wantCache: repo.CacheMetadata{
				UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ETags:     map[string]string{ts.URL + "/archive.zip": "current-etag"},
			},
		},
		{
			name: "update needed (update interval passed)",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, ts.URL+"/archive.zip")

				repoDir := filepath.Join(cacheDir, "vex", "repositories", r.Name)
				testutil.MustMkdirAll(t, filepath.Join(repoDir, "0.1"))

				cacheMetadata := repo.CacheMetadata{
					UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					ETags:     map[string]string{ts.URL + "/archive.zip": "old-etag"},
				}
				testutil.MustWriteJSON(t, filepath.Join(repoDir, "cache.json"), cacheMetadata)
			},
			clockTime: time.Date(2023, 1, 2, 3, 0, 0, 0, time.UTC),
			wantCache: repo.CacheMetadata{
				UpdatedAt: time.Date(2023, 1, 2, 3, 0, 0, 0, time.UTC),
				ETags:     map[string]string{ts.URL + "/archive.zip": "new-etag"},
			},
		},
		{
			name: "no update needed (304 Not Modified)",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, ts.URL+"/archive.zip")

				repoDir := filepath.Join(cacheDir, "vex", "repositories", r.Name)
				testutil.MustMkdirAll(t, filepath.Join(repoDir, "0.1"))

				cacheMetadata := repo.CacheMetadata{
					UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					ETags:     map[string]string{ts.URL + "/archive.zip": "current-etag"},
				}
				testutil.MustWriteJSON(t, filepath.Join(repoDir, "cache.json"), cacheMetadata)
			},
			clockTime: time.Date(2023, 1, 2, 3, 0, 0, 0, time.UTC),
			wantCache: repo.CacheMetadata{
				UpdatedAt: time.Date(2023, 1, 2, 3, 0, 0, 0, time.UTC),
				ETags:     map[string]string{ts.URL + "/archive.zip": "current-etag"},
			},
		},
		{
			name: "update with no existing cache.json",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, ts.URL+"/archive.zip")

				repoDir := filepath.Join(cacheDir, "vex", "repositories", r.Name)
				testutil.MustMkdirAll(t, filepath.Join(repoDir, "0.1"))
			},
			clockTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			wantCache: repo.CacheMetadata{
				UpdatedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				ETags:     map[string]string{ts.URL + "/archive.zip": "new-etag"},
			},
		},
		{
			name:      "manifest not found",
			setup:     func(*testing.T, string, *repo.Repository) {},
			clockTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:   "failed to get the repository metadata",
		},
		{
			name: "download error",
			setup: func(t *testing.T, cacheDir string, r *repo.Repository) {
				setUpManifest(t, cacheDir, ts.URL+"/error")

				repoDir := filepath.Join(cacheDir, "vex", "repositories", r.Name)
				testutil.MustMkdirAll(t, filepath.Join(repoDir, "0.1"))
			},
			clockTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:   "failed to download the repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, m := setupManager(t)
			conf, err := m.Config(context.Background())
			require.NoError(t, err)

			r := conf.Repositories[0]
			r.URL = ts.URL + "/vex-repository.json"
			tt.setup(t, tempDir, &r)

			ctx := clock.With(context.Background(), tt.clockTime)
			err = r.Update(ctx, repo.Options{})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			cacheFile := filepath.Join(tempDir, "vex", "repositories", r.Name, "cache.json")
			var gotCache repo.CacheMetadata
			testutil.MustReadJSON(t, cacheFile, &gotCache)
			assert.Equal(t, tt.wantCache, gotCache)
		})
	}
}

func setupManager(t *testing.T) (string, *repo.Manager) {
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "testdata")
	return tempDir, repo.NewManager(tempDir)
}

func setUpManifest(t *testing.T, dir, url string) {
	manifest := repo.Manifest{
		Name:        "test-repo",
		Description: "test repository",
		Versions: []repo.Version{
			{
				SpecVersion: "0.1",
				Locations: []repo.Location{
					{
						URL: url,
					},
				},
				UpdateInterval: repo.Duration{Duration: time.Hour * 24},
			},
		},
	}
	manifestPath := filepath.Join(dir, "vex", "repositories", "test-repo", "vex-repository.json")
	testutil.MustWriteJSON(t, manifestPath, manifest)
}

func setUpRepository(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/archive.zip":
			if r.Header.Get("If-None-Match") == "current-etag" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("ETag", "new-etag")
			zw := zip.NewWriter(w)
			assert.NoError(t, zw.AddFS(os.DirFS("testdata/test-repo")))
			assert.NoError(t, zw.Close())
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}
