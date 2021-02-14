package analyzer_test

import (
	"errors"
	"io/ioutil"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestAnalysisResult_Merge(t *testing.T) {
	type fields struct {
		m            sync.Mutex
		OS           *types.OS
		PackageInfos []types.PackageInfo
		Applications []types.Application
	}
	type args struct {
		new *analyzer.AnalysisResult
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			fields: fields{
				OS: &types.OS{
					Family: aos.Debian,
					Name:   "9.8",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/libc",
						Packages: []types.Package{
							{Name: "libc", Version: "1.2.3"},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "app/Gemfile.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name: "rails", Version: "5.0.0",
								},
							},
						},
					},
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					PackageInfos: []types.PackageInfo{
						{
							FilePath: "var/lib/dpkg/status.d/openssl",
							Packages: []types.Package{
								{Name: "openssl", Version: "1.1.1"},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     "bundler",
							FilePath: "app2/Gemfile.lock",
							Libraries: []types.LibraryInfo{
								{
									Library: godeptypes.Library{
										Name: "nokogiri", Version: "1.0.0",
									},
								},
							},
						},
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Debian,
					Name:   "9.8",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/libc",
						Packages: []types.Package{
							{Name: "libc", Version: "1.2.3"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/openssl",
						Packages: []types.Package{
							{Name: "openssl", Version: "1.1.1"},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "app/Gemfile.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name: "rails", Version: "5.0.0",
								},
							},
						},
					},
					{
						Type:     "bundler",
						FilePath: "app2/Gemfile.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name: "nokogiri", Version: "1.0.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat must be replaced with oracle",
			fields: fields{
				OS: &types.OS{
					Family: aos.RedHat, // this must be overwritten
					Name:   "8.0",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: &types.OS{
						Family: aos.Oracle,
						Name:   "8.0",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Oracle,
					Name:   "8.0",
				},
			},
		},
		{
			name: "debian must be replaced with ubuntu",
			fields: fields{
				OS: &types.OS{
					Family: aos.Debian, // this must be overwritten
					Name:   "9.0",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: &types.OS{
						Family: aos.Ubuntu,
						Name:   "18.04",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Ubuntu,
					Name:   "18.04",
				},
			},
		},
		{
			name: "alpine must not be replaced with oracle",
			fields: fields{
				OS: &types.OS{
					Family: aos.Alpine, // this must not be overwritten
					Name:   "3.11",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: &types.OS{
						Family: aos.Oracle,
						Name:   "8.0",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: &types.OS{
					Family: aos.Alpine, // this must not be overwritten
					Name:   "3.11",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzer.AnalysisResult{
				OS:           tt.fields.OS,
				PackageInfos: tt.fields.PackageInfos,
				Applications: tt.fields.Applications,
			}
			r.Merge(tt.args.new)
			assert.Equal(t, tt.want, r)
		})
	}
}

func TestAnalyzeFile(t *testing.T) {
	type args struct {
		filePath string
		info     os.FileInfo
		opener   analyzer.Opener
	}
	tests := []struct {
		name    string
		args    args
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "happy path with os analyzer",
			args: args{
				filePath: "/etc/alpine-release",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/etc/alpine-release")
				},
			},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
			},
		},
		{
			name: "happy path with package analyzer",
			args: args{
				filePath: "/lib/apk/db/installed",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/lib/apk/db/installed")
				},
			},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "/lib/apk/db/installed",
						Packages: []types.Package{
							{Name: "musl", Version: "1.1.24-r2", SrcName: "musl", SrcVersion: "1.1.24-r2"},
						},
					},
				},
			},
		},
		{
			name: "happy path with library analyzer",
			args: args{
				filePath: "/app/Gemfile.lock",
				opener: func() ([]byte, error) {
					return ioutil.ReadFile("testdata/app/Gemfile.lock")
				},
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "/app/Gemfile.lock",
						Libraries: []types.LibraryInfo{
							{
								Library: godeptypes.Library{
									Name:    "actioncable",
									Version: "5.2.3",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with invalid os information",
			args: args{
				filePath: "/etc/lsb-release",
				opener: func() ([]byte, error) {
					return []byte(`foo`), nil
				},
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "sad path with opener error",
			args: args{
				filePath: "/lib/apk/db/installed",
				opener: func() ([]byte, error) {
					return nil, xerrors.New("error")
				},
			},
			wantErr: "unable to open a file (/lib/apk/db/installed)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			got := new(analyzer.AnalysisResult)
			err := analyzer.AnalyzeFile(&wg, got, tt.args.filePath, tt.args.info, tt.args.opener)

			wg.Wait()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

type mockConfigAnalyzer struct{}

func (mockConfigAnalyzer) Required(targetOS types.OS) bool {
	return targetOS.Family == "alpine"
}

func (mockConfigAnalyzer) Analyze(targetOS types.OS, configBlob []byte) ([]types.Package, error) {
	if string(configBlob) != `foo` {
		return nil, errors.New("error")
	}
	return []types.Package{
		{Name: "musl", Version: "1.1.24-r2"},
	}, nil
}

func TestAnalyzeConfig(t *testing.T) {
	analyzer.RegisterConfigAnalyzer(mockConfigAnalyzer{})

	type args struct {
		targetOS   types.OS
		configBlob []byte
	}
	tests := []struct {
		name string
		args args
		want []types.Package
	}{
		{
			name: "happy path",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				configBlob: []byte("foo"),
			},
			want: []types.Package{
				{Name: "musl", Version: "1.1.24-r2"},
			},
		},
		{
			name: "non-target OS",
			args: args{
				targetOS: types.OS{
					Family: "debian",
					Name:   "9.2",
				},
				configBlob: []byte("foo"),
			},
		},
		{
			name: "Analyze returns an error",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				configBlob: []byte("bar"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.AnalyzeConfig(tt.args.targetOS, tt.args.configBlob)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  *types.Package
		want bool
	}{
		{
			name: "valid package",
			pkg: &types.Package{
				Name:    "musl",
				Version: "1.2.3",
			},
			want: true,
		},
		{
			name: "empty name",
			pkg: &types.Package{
				Name:    "",
				Version: "1.2.3",
			},
			want: false,
		},
		{
			name: "empty version",
			pkg: &types.Package{
				Name:    "musl",
				Version: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.CheckPackage(tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}
