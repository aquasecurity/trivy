package plugin_test

import (
	"archive/zip"
	"bytes"
	"context"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
)

func TestManager_Run(t *testing.T) {
	if runtime.GOOS == "windows" {
		// the test.sh script can't be run on windows so skipping
		t.Skip("Test satisfied adequately by Linux tests")
	}
	type fields struct {
		Name        string
		Repository  string
		Version     string
		Usage       string
		Description string
		Platforms   []plugin.Platform
		GOOS        string
		GOARCH      string
	}
	tests := []struct {
		name    string
		fields  fields
		opts    plugin.Options
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				Name:        "test_plugin",
				Repository:  "github.com/aquasecurity/trivy-plugin-test",
				Version:     "0.1.0",
				Usage:       "test",
				Description: "test",
				Platforms: []plugin.Platform{
					{
						Selector: &plugin.Selector{
							OS:   "linux",
							Arch: "amd64",
						},
						URI: "github.com/aquasecurity/trivy-plugin-test",
						Bin: "test.sh",
					},
				},
				GOOS:   "linux",
				GOARCH: "amd64",
			},
		},
		{
			name: "no selector",
			fields: fields{
				Name:        "test_plugin",
				Repository:  "github.com/aquasecurity/trivy-plugin-test",
				Version:     "0.1.0",
				Usage:       "test",
				Description: "test",
				Platforms: []plugin.Platform{
					{
						URI: "github.com/aquasecurity/trivy-plugin-test",
						Bin: "test.sh",
					},
				},
			},
		},
		{
			name: "no matched platform",
			fields: fields{
				Name:        "test_plugin",
				Repository:  "github.com/aquasecurity/trivy-plugin-test",
				Version:     "0.1.0",
				Usage:       "test",
				Description: "test",
				Platforms: []plugin.Platform{
					{
						Selector: &plugin.Selector{
							OS:   "darwin",
							Arch: "amd64",
						},
						URI: "github.com/aquasecurity/trivy-plugin-test",
						Bin: "test.sh",
					},
				},
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantErr: "platform not found",
		},
		{
			name: "no execution file",
			fields: fields{
				Name:        "test_plugin",
				Repository:  "github.com/aquasecurity/trivy-plugin-test",
				Version:     "0.1.0",
				Usage:       "test",
				Description: "test",
				Platforms: []plugin.Platform{
					{
						Selector: &plugin.Selector{
							OS:   "linux",
							Arch: "amd64",
						},
						URI: "github.com/aquasecurity/trivy-plugin-test",
						Bin: "nonexistence.sh",
					},
				},
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantErr: "no such file or directory",
		},
		{
			name: "plugin exec error",
			fields: fields{
				Name:        "error_plugin",
				Repository:  "github.com/aquasecurity/trivy-plugin-error",
				Version:     "0.1.0",
				Usage:       "test",
				Description: "test",
				Platforms: []plugin.Platform{
					{
						Selector: &plugin.Selector{
							OS:   "linux",
							Arch: "amd64",
						},
						URI: "github.com/aquasecurity/trivy-plugin-test",
						Bin: "test.sh",
					},
				},
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantErr: "exit status 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", "testdata")

			p := plugin.Plugin{
				Name:        tt.fields.Name,
				Repository:  tt.fields.Repository,
				Version:     tt.fields.Version,
				Usage:       tt.fields.Usage,
				Description: tt.fields.Description,
				Platforms:   tt.fields.Platforms,
			}

			err := p.Run(context.Background(), plugin.Options{
				Platform: ftypes.Platform{
					Platform: &v1.Platform{
						OS:           "linux",
						Architecture: "amd64",
					},
				},
			})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestManager_Install(t *testing.T) {
	if runtime.GOOS == "windows" {
		// the test.sh script can't be run on windows so skipping
		t.Skip("Test satisfied adequately by Linux tests")
	}
	wantPlugin := plugin.Plugin{
		Name:        "test_plugin",
		Repository:  "github.com/aquasecurity/trivy-plugin-test",
		Version:     "0.1.0",
		Usage:       "test",
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
			name:       "index",
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

func TestManager_Uninstall(t *testing.T) {
	ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
	pluginName := "test_plugin"

	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)
	pluginDir := filepath.Join(tempDir, ".trivy", "plugins", pluginName)

	t.Run("plugin found", func(t *testing.T) {
		// Create the test plugin directory
		err := os.MkdirAll(pluginDir, os.ModePerm)
		require.NoError(t, err)

		// Create the test file
		err = os.WriteFile(filepath.Join(pluginDir, "test.sh"), []byte(`foo`), os.ModePerm)
		require.NoError(t, err)

		// Uninstall the plugin
		err = plugin.NewManager().Uninstall(ctx, pluginName)
		assert.NoError(t, err)
		assert.NoDirExists(t, pluginDir)
	})

	t.Run("plugin not found", func(t *testing.T) {
		t.Setenv("NO_COLOR", tempDir)
		buf := bytes.NewBuffer(nil)
		slog.SetDefault(slog.New(log.NewHandler(buf, &log.Options{Level: log.LevelInfo})))

		err := plugin.NewManager().Uninstall(ctx, pluginName)
		assert.NoError(t, err)
		assert.Equal(t, "2021-08-25T12:20:30Z\tERROR\t[plugin] No such plugin\n", buf.String())
	})
}

func TestManager_Information(t *testing.T) {
	pluginName := "test_plugin"

	tempDir := t.TempDir()
	pluginDir := filepath.Join(tempDir, ".trivy", "plugins", pluginName)

	t.Setenv("XDG_DATA_HOME", tempDir)

	// Create the test plugin directory
	err := os.MkdirAll(pluginDir, os.ModePerm)
	require.NoError(t, err)

	// write the plugin name
	pluginMetadata := `name: "test_plugin"
repository: github.com/aquasecurity/trivy-plugin-test
version: "0.1.0"
usage: test
description: A simple test plugin`

	err = os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(pluginMetadata), os.ModePerm)
	require.NoError(t, err)

	var got bytes.Buffer
	manager := plugin.NewManager(plugin.WithWriter(&got))

	// Get Information for the plugin
	err = manager.Information(pluginName)
	require.NoError(t, err)
	assert.Equal(t, "\nPlugin: test_plugin\n  Description: A simple test plugin\n  Version:     0.1.0\n  Usage:       test\n", got.String())
	got.Reset()

	// Get Information for unknown plugin
	err = manager.Information("unknown")
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not find a plugin called 'unknown', did you install it?")
}

func TestManager_LoadAll(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    []plugin.Plugin
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata",
			want: []plugin.Plugin{
				{
					Name:        "test_plugin",
					Repository:  "github.com/aquasecurity/trivy-plugin-test",
					Version:     "0.1.0",
					Usage:       "test",
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
				},
			},
		},
		{
			name:    "sad path",
			dir:     "sad",
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tt.dir)

			got, err := plugin.NewManager().LoadAll(context.Background())
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			require.Len(t, got, len(tt.want))
			for i := range tt.want {
				assert.EqualExportedValues(t, tt.want[i], got[i])
			}
		})
	}
}

func TestManager_Upgrade(t *testing.T) {
	if runtime.GOOS == "windows" {
		// the test.sh script can't be run on windows so skipping
		t.Skip("Test satisfied adequately by Linux tests")
	}
	pluginName := "test_plugin"

	tempDir := t.TempDir()
	pluginDir := filepath.Join(tempDir, ".trivy", "plugins", pluginName)

	t.Setenv("XDG_DATA_HOME", tempDir)

	// Create the test plugin directory
	err := os.MkdirAll(pluginDir, os.ModePerm)
	require.NoError(t, err)

	// write the plugin name
	pluginMetadata := `name: "test_plugin"
repository: testdata/test_plugin
version: "0.0.5"
usage: test
description: A simple test plugin
installed:
	platform:
		os: linux
		arch: amd64`

	err = os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(pluginMetadata), os.ModePerm)
	require.NoError(t, err)

	ctx := context.Background()
	m := plugin.NewManager()

	// verify initial version
	verifyVersion(t, ctx, m, pluginName, "0.0.5")

	// Upgrade the existing plugin
	err = m.Upgrade(ctx, nil)
	require.NoError(t, err)

	// verify plugin updated
	verifyVersion(t, ctx, m, pluginName, "0.1.0")
}

func verifyVersion(t *testing.T, ctx context.Context, m *plugin.Manager, pluginName, expectedVersion string) {
	plugins, err := m.LoadAll(ctx)
	require.NoError(t, err)
	for _, p := range plugins {
		if p.Name == pluginName {
			assert.Equal(t, expectedVersion, p.Version)
		}
	}
}
