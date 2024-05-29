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

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/sosedoff/gitkit" // Not work on Windows
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func setupGitServer() (*httptest.Server, error) {
	service := gitkit.New(gitkit.Config{
		Dir:        "./testdata",
		AutoCreate: false,
	})

	if err := service.Setup(); err != nil {
		return nil, err
	}

	ts := httptest.NewServer(service)

	return ts, nil
}

func TestManager_Install(t *testing.T) {
	gs, err := setupGitServer()
	require.NoError(t, err)
	t.Cleanup(gs.Close)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr := zip.NewWriter(w)
		require.NoError(t, zr.AddFS(os.DirFS("testdata/test_plugin")))
		require.NoError(t, zr.Close())
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
	wantPluginWithVersion := wantPlugin
	wantPluginWithVersion.Version = "0.1.0"

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
			name:       "local path",
			pluginName: "testdata/test_plugin",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "testdata/test_plugin", "0.2.0"),
		},
		{
			name:       "git",
			pluginName: "git::" + gs.URL + "/test_plugin.git",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "git::"+gs.URL+"/test_plugin.git", "0.2.0"),
		},
		{
			name:       "with version",
			pluginName: "git::" + gs.URL + "/test_plugin.git@v0.1.0",
			want:       wantPluginWithVersion,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
			wantLogs:   fmt.Sprintf(wantLogs, "git::"+gs.URL+"/test_plugin.git", "0.1.0"),
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
			fsutils.SetCacheDir("testdata")

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
