package plugin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"
)

func TestPlugin_Run(t *testing.T) {
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
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
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
			wantErr: "plugin exec: exit status 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("XDG_DATA_HOME", "testdata")
			defer os.Unsetenv("XDG_DATA_HOME")

			p := plugin.Plugin{
				Name:        tt.fields.Name,
				Repository:  tt.fields.Repository,
				Version:     tt.fields.Version,
				Usage:       tt.fields.Usage,
				Description: tt.fields.Description,
				Platforms:   tt.fields.Platforms,
				GOOS:        tt.fields.GOOS,
				GOARCH:      tt.fields.GOARCH,
			}

			err := p.Run(context.Background(), tt.args.args)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestInstall(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		want     plugin.Plugin
		wantFile string
		wantErr  string
	}{
		{
			name: "happy path",
			url:  "testdata/test_plugin",
			want: plugin.Plugin{
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
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantFile: ".trivy/plugins/test_plugin/test.sh",
		},
		{
			name: "plugin not found",
			url:  "testdata/not_found",
			want: plugin.Plugin{
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
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantErr: "no such file or directory",
		},
		{
			name: "no plugin.yaml",
			url:  "testdata/no_yaml",
			want: plugin.Plugin{
				Name:        "no_yaml",
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
				GOOS:   "linux",
				GOARCH: "amd64",
			},
			wantErr: "file open error",
		},
	}

	log.InitLogger(false, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The test plugin will be installed here
			dst := t.TempDir()
			os.Setenv("XDG_DATA_HOME", dst)

			got, err := plugin.Install(context.Background(), tt.url, false)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
			assert.FileExists(t, filepath.Join(dst, tt.wantFile))
		})
	}
}

func TestUninstall(t *testing.T) {
	pluginName := "test_plugin"

	tempDir := t.TempDir()
	pluginDir := filepath.Join(tempDir, ".trivy", "plugins", pluginName)

	// Create the test plugin directory
	err := os.MkdirAll(pluginDir, os.ModePerm)
	require.NoError(t, err)

	// Create the test file
	err = os.WriteFile(filepath.Join(pluginDir, "test.sh"), []byte(`foo`), os.ModePerm)
	require.NoError(t, err)

	// Uninstall the plugin
	err = plugin.Uninstall(pluginName)
	assert.NoError(t, err)
	assert.NoFileExists(t, pluginDir)
}

func TestLoadAll1(t *testing.T) {
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
					GOOS:   "linux",
					GOARCH: "amd64",
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
			os.Setenv("XDG_DATA_HOME", tt.dir)
			defer os.Unsetenv("XDG_DATA_HOME")

			got, err := plugin.LoadAll()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
