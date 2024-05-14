//go:build unix

package plugin_test

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sosedoff/gitkit" // Not work on Windows
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	ts, err := setupGitServer()
	require.NoError(t, err)
	defer ts.Close()

	wantPlugin := plugin.Plugin{
		Name:        "test_plugin",
		Repository:  "github.com/aquasecurity/trivy-plugin-test",
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

	tests := []struct {
		name       string
		pluginName string
		want       plugin.Plugin
		wantFile   string
		wantErr    string
	}{
		{
			name:     "http",
			want:     wantPlugin,
			wantFile: ".trivy/plugins/test_plugin/test.sh",
		},
		{
			name:       "local path",
			pluginName: "testdata/test_plugin",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
		},
		{
			name:       "git",
			pluginName: "git::" + ts.URL + "/test_plugin.git",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
		},
		{
			name:       "with version",
			pluginName: "git::" + ts.URL + "/test_plugin.git@v0.1.0",
			want:       wantPluginWithVersion,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
		},
		{
			name:       "via index",
			pluginName: "test",
			want:       wantPlugin,
			wantFile:   ".trivy/plugins/test_plugin/test.sh",
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

			if tt.pluginName == "" {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					zr := zip.NewWriter(w)
					require.NoError(t, zr.AddFS(os.DirFS("testdata/test_plugin")))
					require.NoError(t, zr.Close())
				}))
				t.Cleanup(ts.Close)
				tt.pluginName = ts.URL + "/test_plugin.zip"
			}

			got, err := plugin.NewManager().Install(context.Background(), tt.pluginName, plugin.Options{
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
			assert.NoError(t, err)

			assert.EqualExportedValues(t, tt.want, got)
			assert.FileExists(t, filepath.Join(dst, tt.wantFile))
		})
	}
}
