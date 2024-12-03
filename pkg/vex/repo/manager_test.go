package repo_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

func TestManager_Config(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, string)
		want    repo.Config
		wantErr string
	}{
		{
			name: "config file exists",
			setup: func(t *testing.T, dir string) {
				config := repo.Config{
					Repositories: []repo.Repository{
						{
							Name:    "test-repo",
							URL:     "https://example.com/repo",
							Enabled: true,
						},
					},
				}
				configPath := filepath.Join(dir, ".trivy", "vex", "repository.yaml")
				testutil.MustWriteYAML(t, configPath, config)
			},
			want: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "test-repo",
						URL:     "https://example.com/repo",
						Enabled: true,
					},
				},
			},
		},
		{
			name:  "config file does not exist",
			setup: func(t *testing.T, dir string) {},
			want: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "default",
						URL:     "https://github.com/aquasecurity/vexhub",
						Enabled: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)
			m := repo.NewManager(tempDir)

			tt.setup(t, tempDir)

			got, err := m.Config(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.EqualExportedValues(t, tt.want, got)
		})
	}
}

func TestManager_Init(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, string)
		want    repo.Config
		wantErr string
	}{
		{
			name:  "successful init",
			setup: func(t *testing.T, dir string) {},
			want: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "default",
						URL:     "https://github.com/aquasecurity/vexhub",
						Enabled: true,
					},
				},
			},
		},
		{
			name: "config already exists",
			setup: func(t *testing.T, dir string) {
				configPath := filepath.Join(dir, ".trivy", "vex", "repository.yaml")
				testutil.MustWriteYAML(t, configPath, repo.Config{})
			},
			want: repo.Config{
				Repositories: []repo.Repository{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)
			m := repo.NewManager(tempDir)

			tt.setup(t, tempDir)

			err := m.Init(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			configPath := filepath.Join(tempDir, ".trivy", "vex", "repository.yaml")
			assert.FileExists(t, configPath)

			var got repo.Config
			testutil.MustReadYAML(t, configPath, &got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManager_DownloadRepositories(t *testing.T) {
	ts := setUpRepository(t)
	defer ts.Close()

	tests := []struct {
		name         string
		config       repo.Config
		location     string
		names        []string
		wantErr      string
		wantDownload bool
	}{
		{
			name: "successful download",
			config: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "test-repo",
						URL:     ts.URL,
						Enabled: true,
					},
				},
			},
			location:     ts.URL + "/archive.zip",
			wantDownload: true,
		},
		{
			name: "no enabled repositories",
			config: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "test-repo",
						URL:     "https://localhost:10000", // Will not be reached
						Enabled: false,
					},
				},
			},
			location:     ts.URL + "/archive.zip",
			wantDownload: false,
		},
		{
			name: "download specific repository",
			config: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "another-repo",
						URL:     "https://example.com/repo",
						Enabled: true,
					},
					{
						Name:    "test-repo",
						URL:     ts.URL,
						Enabled: true,
					},
				},
			},
			location:     ts.URL + "/archive.zip",
			names:        []string{"test-repo"},
			wantDownload: true,
		},
		{
			name: "download error",
			config: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "test-repo",
						URL:     ts.URL,
						Enabled: true,
					},
				},
			},
			location:     ts.URL + "/error",
			wantErr:      "failed to download the repository",
			wantDownload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)
			m := repo.NewManager(tempDir)

			configPath := filepath.Join(tempDir, ".trivy", "vex", "repository.yaml")
			testutil.MustWriteYAML(t, configPath, tt.config)

			manifestPath := filepath.Join(tempDir, "vex", "repositories", "test-repo", "vex-repository.json")
			manifest.Versions[0].Locations[0].URL = tt.location
			testutil.MustWriteJSON(t, manifestPath, manifest)

			err := m.DownloadRepositories(context.Background(), tt.names, repo.Options{})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Check if the repository was downloaded
			if tt.wantDownload {
				repoDir := filepath.Join(tempDir, "vex", "repositories", "test-repo")
				assert.DirExists(t, repoDir)
				assert.FileExists(t, filepath.Join(repoDir, "vex-repository.json"))
				assert.FileExists(t, filepath.Join(repoDir, "0.1", "index.json"))
			}
		})
	}
}

func TestManager_List(t *testing.T) {
	tests := []struct {
		name    string
		config  repo.Config
		want    string
		wantErr string
	}{
		{
			name: "list repositories",
			config: repo.Config{
				Repositories: []repo.Repository{
					{
						Name:    "default",
						URL:     "https://github.com/aquasecurity/vexhub",
						Enabled: true,
					},
					{
						Name:    "custom",
						URL:     "https://example.com/custom-vex-repo",
						Enabled: false,
					},
				},
			},
			want: `VEX Repositories (config: %s)

- Name: default
  URL: https://github.com/aquasecurity/vexhub
  Status: Enabled

- Name: custom
  URL: https://example.com/custom-vex-repo
  Status: Disabled

`,
		},
		{
			name: "no repositories",
			config: repo.Config{
				Repositories: []repo.Repository{},
			},
			want: `VEX Repositories (config: %s)

No repositories configured.
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", tempDir)
			configPath := filepath.Join(tempDir, ".trivy", "vex", "repository.yaml")
			testutil.MustWriteYAML(t, configPath, tt.config)

			var buf bytes.Buffer
			m := repo.NewManager(tempDir, repo.WithWriter(&buf))

			err := m.List(context.Background())
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			want := fmt.Sprintf(tt.want, configPath)
			require.NoError(t, err)
			assert.Equal(t, want, buf.String())
		})
	}
}

func TestManager_Clear(t *testing.T) {
	tempDir := t.TempDir()
	m := repo.NewManager(tempDir)

	// Create some dummy files
	cacheDir := filepath.Join(tempDir, "vex")
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	dummyFile := filepath.Join(cacheDir, "dummy.txt")
	require.NoError(t, os.WriteFile(dummyFile, []byte("dummy"), 0644))

	err := m.Clear()
	require.NoError(t, err)

	// Check if the cache directory was removed
	_, err = os.Stat(cacheDir)
	assert.True(t, os.IsNotExist(err))
}
