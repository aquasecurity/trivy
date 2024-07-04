//go:build unix

package plugin_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/gittest"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func setupGitRepository(t *testing.T, repo, dir string) *httptest.Server {
	gs := gittest.NewServer(t, repo, dir)

	worktree := t.TempDir()
	r := gittest.Clone(t, gs, repo, worktree)

	// git tag
	gittest.SetTag(t, r, "v0.2.0")

	// git commit
	modifyManifest(t, worktree, "0.3.0")
	gittest.CommitAll(t, r, "bump up to 0.3.0")

	err := r.Push(&git.PushOptions{})
	require.NoError(t, err)

	// git tag
	gittest.SetTag(t, r, "v0.3.0")

	// git push --tags
	gittest.PushTags(t, r)

	return gs
}

func modifyManifest(t *testing.T, worktree, version string) {
	manifestPath := filepath.Join(worktree, "plugin.yaml")
	b, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	b = bytes.ReplaceAll(b, []byte("0.2.0"), []byte(version))
	err = os.WriteFile(manifestPath, b, 0644)
	require.NoError(t, err)
}

func TestManager_Install(t *testing.T) {
	gs := setupGitRepository(t, "test_plugin", "testdata/test_plugin/test_plugin")
	t.Cleanup(gs.Close)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr := zip.NewWriter(w)
		switch r.URL.Path {
		case "/test_plugin.zip":
			assert.NoError(t, zr.AddFS(os.DirFS("testdata/test_plugin/test_plugin")))
		case "/test_nested.zip":
			assert.NoError(t, zr.AddFS(os.DirFS("testdata/test_plugin")))
		}
		assert.NoError(t, zr.Close())
	}))
	t.Cleanup(ts.Close)

	wantPlugin := plugin.Plugin{
		Name:        "test_plugin",
		Repository:  "testdata/test_plugin",
		Version:     "0.2.0",
		Summary:     "test",
		Description: "test",
		Platforms: []plugin.Platform{
			{
				Selector: &plugin.Selector{
					OS:   "linux",
					Arch: "amd64",
				},
				URI: "./test.sh",
				Bin: "./test.sh",
			},
		},
		Installed: plugin.Installed{
			Platform: plugin.Selector{
				OS:   "linux",
				Arch: "amd64",
			},
		},
	}
	wantPluginWithGit := wantPlugin
	wantPluginWithGit.Version = "0.3.0"

	wantLogs := `2021-08-25T12:20:30Z	INFO	Installing the plugin...	src="%s"
2021-08-25T12:20:30Z	INFO	Plugin successfully installed	name="test_plugin" version="%s"
`

	tests := []struct {
		name       string
		pluginName string
		installed  *plugin.Plugin
		want       plugin.Plugin
		wantFile   string
		wantLogs   string
		wantErr    string
	}{
		{
			name:       "http",
			pluginName: ts.URL + "/test_plugin.zip",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, ts.URL+"/test_plugin.zip", "0.2.0"),
		},
		{
			name:       "nested archive",
			pluginName: ts.URL + "/test_nested.zip",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, ts.URL+"/test_nested.zip", "0.2.0"),
		},
		{
			name:       "local path",
			pluginName: "testdata/test_plugin",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "testdata/test_plugin", "0.2.0"),
		},
		{
			name:       "git",
			pluginName: "git::" + gs.URL + "/test_plugin.git",
			want:       wantPluginWithGit,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "git::"+gs.URL+"/test_plugin.git", "0.3.0"),
		},
		{
			name:       "with version",
			pluginName: "git::" + gs.URL + "/test_plugin.git@v0.2.0",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "git::"+gs.URL+"/test_plugin.git", "0.2.0"),
		},
		{
			name:       "via index",
			pluginName: "test_plugin",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "testdata/test_plugin", "0.2.0"),
		},
		{
			name:       "installed",
			pluginName: "test_plugin",
			installed: &plugin.Plugin{
				Name:       "test_plugin",
				Repository: "testdata/test_plugin",
				Version:    "0.2.0",
			},
			want:     wantPlugin,
			wantLogs: "2021-08-25T12:20:30Z	INFO	The plugin is already installed	name=\"test_plugin\"\n",
		},
		{
			name:       "different version installed",
			pluginName: "test_plugin@v0.2.0",
			installed: &plugin.Plugin{
				Name:       "test_plugin",
				Repository: "testdata/test_plugin",
				Version:    "0.1.0",
			},
			want:     wantPlugin,
			wantLogs: fmt.Sprintf(wantLogs, "testdata/test_plugin", "0.2.0"),
		},
		{
			name:       "plugin not found",
			pluginName: "testdata/not_found",
			wantErr:    "no such file or directory",
		},
		{
			name:       "no plugin.yaml",
			pluginName: "testdata/no_yaml",
			wantErr:    "file open error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The test plugin will be installed here
			dst := t.TempDir()
			t.Setenv("XDG_DATA_HOME", dst)

			// For plugin index
			pluginDir := filepath.Join(dst, ".trivy", "plugins")
			err := os.MkdirAll(pluginDir, 0755)
			require.NoError(t, err)
			_, err = fsutils.CopyFile("testdata/.trivy/plugins/index.yaml", filepath.Join(pluginDir, "index.yaml"))
			require.NoError(t, err)

			if tt.installed != nil {
				setupInstalledPlugin(t, dst, *tt.installed)
			}

			var gotLogs bytes.Buffer
			logger := log.New(log.NewHandler(&gotLogs, nil))

			ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

			got, err := plugin.NewManager(plugin.WithLogger(logger)).Install(ctx, tt.pluginName, plugin.Options{
				Platform: ftypes.Platform{
					Platform: &v1.Platform{
						Architecture: "amd64",
						OS:           "linux",
					},
				},
			})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.EqualExportedValues(t, tt.want, got)
			if tt.wantFile != "" {
				assert.FileExists(t, filepath.Join(dst, tt.wantFile))
			}
			assert.Equal(t, tt.wantLogs, gotLogs.String())
		})
	}
}
