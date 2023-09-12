package nodejs

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_systemFileFilterHook_Hook(t *testing.T) {
	tests := []struct {
		name   string
		result *analyzer.AnalysisResult
		blob   *types.BlobInfo
		want   *types.BlobInfo
	}{
		{
			name: "happy path",
			result: &analyzer.AnalysisResult{
				SystemInstalledFiles: []string{
					"/",
					"/usr/bin/pydoc",
					"/usr/bin/python",
					"/usr/bin/python2",
					"/usr/bin/python2.7",
					"/usr/libexec/platform-python",
					"/usr/share/doc/python-2.7.5",
					"/usr/share/doc/python-2.7.5/LICENSE",
					"/usr/share/doc/python-2.7.5/README",
					"/usr/share/man/man1/python.1.gz",
					"/usr/share/man/man1/python2.1.gz",
					"/usr/share/man/man1/python2.7.1.gz",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.py",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.pyc",
					"/usr/lib64/python2.7/distutils/command/install_egg_info.pyo",
					"/usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
					"usr/lib64/python2.7/wsgiref.egg-info", // without the leading slash
				},
			},
			blob: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: types.Packages{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: types.Packages{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type: types.PythonPkg,
						Libraries: types.Packages{
							{
								Name:     "python",
								Version:  "2.7.5",
								FilePath: "usr/lib64/python2.7/lib-dynload/Python-2.7.5-py2.7.egg-info",
							},
							{
								Name:     "pycurl",
								Version:  "7.19.0",
								FilePath: "usr/lib64/python2.7/site-packages/pycurl-7.19.0-py2.7.egg-info",
							},
						},
					},
					{
						Type:     types.PythonPkg,
						FilePath: "usr/lib64/python2.7/wsgiref.egg-info",
						Libraries: types.Packages{
							{
								Name:    "wsgiref",
								Version: "0.1.2",
							},
						},
					},
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goBinariryFile",
						Libraries: types.Packages{
							{
								Name:     "cloud.google.com/go",
								Version:  "v0.81.0",
								FilePath: "",
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
					{
						FilePath: "usr/bin/pydoc/needed",
						Data:     "shouldNotRemove",
					},
				},
			},
			want: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: types.Packages{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: types.Packages{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type: types.PythonPkg,
						Libraries: types.Packages{
							{
								Name:     "pycurl",
								Version:  "7.19.0",
								FilePath: "usr/lib64/python2.7/site-packages/pycurl-7.19.0-py2.7.egg-info",
							},
						},
					},
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goBinariryFile",
						Libraries: types.Packages{
							{
								Name:    "cloud.google.com/go",
								Version: "v0.81.0",
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						FilePath: "usr/bin/pydoc/needed",
						Data:     "shouldNotRemove",
						Layer:    types.Layer{},
					},
				},
			},
		},
		{
			name:   "distoless",
			result: &analyzer.AnalysisResult{},
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
						Libraries: types.Packages{
							{
								Name:     "python",
								Version:  "2.7.14",
								FilePath: "usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{},
		},
		{
			name: "go binaries",
			result: &analyzer.AnalysisResult{
				SystemInstalledFiles: []string{
					"usr/local/bin/goreleaser",
				},
			},
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "usr/local/bin/goreleaser",
						Libraries: types.Packages{
							{
								Name:    "github.com/sassoftware/go-rpmutils",
								Version: "v0.0.0-20190420191620-a8f1baeba37b",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{},
		},
		{
			name: "Rust will not be skipped",
			result: &analyzer.AnalysisResult{
				SystemInstalledFiles: []string{
					"app/Cargo.lock",
				},
			},
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "app/Cargo.lock",
						Libraries: types.Packages{
							{
								Name:    "ghash",
								Version: "0.4.4",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "app/Cargo.lock",
						Libraries: types.Packages{
							{
								Name:    "ghash",
								Version: "0.4.4",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := systemFileFilteringPostHandler{}
			err := h.Handle(context.TODO(), tt.result, tt.blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.blob)
		})
	}
}
