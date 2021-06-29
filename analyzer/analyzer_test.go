package analyzer_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	_ "github.com/aquasecurity/fanal/analyzer/all"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

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

func (mockConfigAnalyzer) Type() analyzer.Type {
	return analyzer.Type("test")
}

func (mockConfigAnalyzer) Version() int {
	return 1
}

func TestMain(m *testing.M) {
	analyzer.RegisterConfigAnalyzer(mockConfigAnalyzer{})
	os.Exit(m.Run())
}

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
		filePath          string
		testFilePath      string
		disabledAnalyzers []analyzer.Type
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
				filePath:     "/etc/alpine-release",
				testFilePath: "testdata/etc/alpine-release",
			},
			want: &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
			},
		},
		{
			name: "happy path with disabled os analyzer",
			args: args{
				filePath:          "/etc/alpine-release",
				testFilePath:      "testdata/etc/alpine-release",
				disabledAnalyzers: []analyzer.Type{analyzer.TypeAlpine},
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "happy path with package analyzer",
			args: args{
				filePath:     "/lib/apk/db/installed",
				testFilePath: "testdata/lib/apk/db/installed",
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
			name: "happy path with disabled package analyzer",
			args: args{
				filePath:          "/lib/apk/db/installed",
				testFilePath:      "testdata/lib/apk/db/installed",
				disabledAnalyzers: []analyzer.Type{analyzer.TypeApk},
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "happy path with library analyzer",
			args: args{
				filePath:     "/app/Gemfile.lock",
				testFilePath: "testdata/app/Gemfile.lock",
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
				filePath:     "/etc/lsb-release",
				testFilePath: "testdata/etc/hostname",
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "happy path with a directory",
			args: args{
				filePath:     "/etc/lsb-release",
				testFilePath: "testdata/etc",
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "sad path with opener error",
			args: args{
				filePath:     "/lib/apk/db/installed",
				testFilePath: "testdata/error",
			},
			wantErr: "unable to open a file (/lib/apk/db/installed)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			limit := semaphore.NewWeighted(3)

			got := new(analyzer.AnalysisResult)
			a := analyzer.NewAnalyzer(tt.args.disabledAnalyzers)

			info, err := os.Stat(tt.args.testFilePath)
			require.NoError(t, err)

			ctx := context.Background()
			err = a.AnalyzeFile(ctx, &wg, limit, got, "", tt.args.filePath, info, func() ([]byte, error) {
				if tt.args.testFilePath == "testdata/error" {
					return nil, xerrors.New("error")
				}
				return os.ReadFile(tt.args.testFilePath)
			})

			wg.Wait()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnalyzeConfig(t *testing.T) {

	type args struct {
		targetOS          types.OS
		configBlob        []byte
		disabledAnalyzers []analyzer.Type
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
			a := analyzer.NewAnalyzer(tt.args.disabledAnalyzers)
			got := a.AnalyzeImageConfig(tt.args.targetOS, tt.args.configBlob)
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

func TestAnalyzer_AnalyzerVersions(t *testing.T) {
	tests := []struct {
		name     string
		disabled []analyzer.Type
		want     map[string]int
	}{
		{
			name:     "happy path",
			disabled: []analyzer.Type{},
			want: map[string]int{
				"alpine":   1,
				"amazon":   1,
				"apk":      1,
				"bundler":  1,
				"cargo":    1,
				"centos":   1,
				"composer": 1,
				"debian":   1,
				"dpkg":     1,
				"fedora":   1,
				"gobinary": 1,
				"gomod":    1,
				"jar":      1,
				"npm":      1,
				"nuget":    1,
				"oracle":   1,
				"photon":   1,
				"pipenv":   1,
				"poetry":   1,
				"redhat":   1,
				"rpm":      1,
				"suse":     1,
				"ubuntu":   1,
				"yarn":     1,
			},
		},
		{
			name:     "disable analyzers",
			disabled: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeUbuntu},
			want: map[string]int{
				"alpine":   0,
				"amazon":   1,
				"apk":      1,
				"bundler":  1,
				"cargo":    1,
				"centos":   1,
				"composer": 1,
				"debian":   1,
				"dpkg":     1,
				"fedora":   1,
				"gobinary": 1,
				"gomod":    1,
				"jar":      1,
				"npm":      1,
				"nuget":    1,
				"oracle":   1,
				"photon":   1,
				"pipenv":   1,
				"poetry":   1,
				"redhat":   1,
				"rpm":      1,
				"suse":     1,
				"ubuntu":   0,
				"yarn":     1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analyzer.NewAnalyzer(tt.disabled)
			got := a.AnalyzerVersions()
			fmt.Printf("%v\n", got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnalyzer_ImageConfigAnalyzerVersions(t *testing.T) {
	tests := []struct {
		name     string
		disabled []analyzer.Type
		want     map[string]int
	}{
		{
			name:     "happy path",
			disabled: []analyzer.Type{},
			want: map[string]int{
				"apk-command": 1,
				"test":        1,
			},
		},
		{
			name:     "disable analyzers",
			disabled: []analyzer.Type{analyzer.TypeAlpine, analyzer.TypeApkCommand},
			want: map[string]int{
				"apk-command": 0,
				"test":        1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analyzer.NewAnalyzer(tt.disabled)
			got := a.ImageConfigAnalyzerVersions()
			assert.Equal(t, tt.want, got)
		})
	}
}
