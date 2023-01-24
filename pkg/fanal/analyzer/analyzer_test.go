package analyzer_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/command/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/repo/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/all"
)

type mockConfigAnalyzer struct{}

func (mockConfigAnalyzer) Required(targetOS types.OS) bool {
	return targetOS.Family == "alpine"
}

func (mockConfigAnalyzer) Analyze(input analyzer.ConfigAnalysisInput) (*analyzer.AnalysisResult, error) {
	if input.Config == nil {
		return nil, errors.New("error")
	}
	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				Packages: types.Packages{
					{
						Name:    "musl",
						Version: "1.1.24-r2",
					},
				},
			},
		},
	}, nil
}

func (mockConfigAnalyzer) Type() analyzer.Type {
	return analyzer.Type("test")
}

func (mockConfigAnalyzer) Version() int {
	return 1
}

func TestMain(m *testing.M) {
	mock := mockConfigAnalyzer{}
	analyzer.RegisterConfigAnalyzer(mock)
	defer analyzer.DeregisterConfigAnalyzer(mock.Type())
	os.Exit(m.Run())
}

func TestAnalysisResult_Merge(t *testing.T) {
	type fields struct {
		m            sync.Mutex
		OS           types.OS
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
				OS: types.OS{
					Family: aos.Debian,
					Name:   "9.8",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/libc",
						Packages: []types.Package{
							{
								Name:    "libc",
								Version: "1.2.3",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "app/Gemfile.lock",
						Libraries: []types.Package{
							{
								Name:    "rails",
								Version: "5.0.0",
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
								{
									Name:    "openssl",
									Version: "1.1.1",
								},
							},
						},
					},
					Applications: []types.Application{
						{
							Type:     "bundler",
							FilePath: "app2/Gemfile.lock",
							Libraries: []types.Package{
								{
									Name:    "nokogiri",
									Version: "1.0.0",
								},
							},
						},
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Debian,
					Name:   "9.8",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/libc",
						Packages: []types.Package{
							{
								Name:    "libc",
								Version: "1.2.3",
							},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/openssl",
						Packages: []types.Package{
							{
								Name:    "openssl",
								Version: "1.1.1",
							},
						},
					},
				},
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "app/Gemfile.lock",
						Libraries: []types.Package{
							{
								Name:    "rails",
								Version: "5.0.0",
							},
						},
					},
					{
						Type:     "bundler",
						FilePath: "app2/Gemfile.lock",
						Libraries: []types.Package{
							{
								Name:    "nokogiri",
								Version: "1.0.0",
							},
						},
					},
				},
			},
		},
		{
			name: "redhat must be replaced with oracle",
			fields: fields{
				OS: types.OS{
					Family: aos.RedHat, // this must be overwritten
					Name:   "8.0",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: types.OS{
						Family: aos.Oracle,
						Name:   "8.0",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Oracle,
					Name:   "8.0",
				},
			},
		},
		{
			name: "debian must be replaced with ubuntu",
			fields: fields{
				OS: types.OS{
					Family: aos.Debian, // this must be overwritten
					Name:   "9.0",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: types.OS{
						Family: aos.Ubuntu,
						Name:   "18.04",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Ubuntu,
					Name:   "18.04",
				},
			},
		},
		{
			name: "merge extended flag",
			fields: fields{
				// This must be overwritten
				OS: types.OS{
					Family: aos.Ubuntu,
					Name:   "16.04",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: types.OS{
						Family:   aos.Ubuntu,
						Extended: true,
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
					Family:   aos.Ubuntu,
					Name:     "16.04",
					Extended: true,
				},
			},
		},
		{
			name: "alpine OS needs to be extended with apk repositories",
			fields: fields{
				OS: types.OS{
					Family: aos.Alpine,
					Name:   "3.15.3",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					Repository: &types.Repository{
						Family:  aos.Alpine,
						Release: "edge",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
					Family: aos.Alpine,
					Name:   "3.15.3",
				},
				Repository: &types.Repository{
					Family:  aos.Alpine,
					Release: "edge",
				},
			},
		},
		{
			name: "alpine must not be replaced with oracle",
			fields: fields{
				OS: types.OS{
					Family: aos.Alpine, // this must not be overwritten
					Name:   "3.11",
				},
			},
			args: args{
				new: &analyzer.AnalysisResult{
					OS: types.OS{
						Family: aos.Oracle,
						Name:   "8.0",
					},
				},
			},
			want: analyzer.AnalysisResult{
				OS: types.OS{
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
		filePatterns      []string
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
				OS: types.OS{
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
							{
								ID:         "musl@1.1.24-r2",
								Name:       "musl",
								Version:    "1.1.24-r2",
								SrcName:    "musl",
								SrcVersion: "1.1.24-r2",
								Licenses:   []string{"MIT"},
							},
						},
					},
				},
				SystemInstalledFiles: []string{
					"lib/libc.musl-x86_64.so.1",
					"lib/ld-musl-x86_64.so.1",
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
						Libraries: []types.Package{
							{
								Name:    "actioncable",
								Version: "5.2.3",
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
			name: "happy path with library analyzer file pattern regex",
			args: args{
				filePath:     "/app/Gemfile-dev.lock",
				testFilePath: "testdata/app/Gemfile.lock",
				filePatterns: []string{"bundler:Gemfile(-.*)?\\.lock"},
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     "bundler",
						FilePath: "/app/Gemfile-dev.lock",
						Libraries: []types.Package{
							{
								Name:    "actioncable",
								Version: "5.2.3",
							},
						},
					},
				},
			},
		},
		{
			name: "ignore permission error",
			args: args{
				filePath:     "/etc/alpine-release",
				testFilePath: "testdata/no-permission",
			},
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "sad path with opener error",
			args: args{
				filePath:     "/lib/apk/db/installed",
				testFilePath: "testdata/error",
			},
			wantErr: "unable to open /lib/apk/db/installed",
		},
		{
			name: "sad path with broken file pattern regex",
			args: args{
				filePath:     "/app/Gemfile-dev.lock",
				testFilePath: "testdata/app/Gemfile.lock",
				filePatterns: []string{"bundler:Gemfile(-.*?\\.lock"},
			},
			wantErr: "error parsing regexp",
		},
		{
			name: "sad path with broken file pattern",
			args: args{
				filePath:     "/app/Gemfile-dev.lock",
				testFilePath: "testdata/app/Gemfile.lock",
				filePatterns: []string{"Gemfile(-.*)?\\.lock"},
			},
			wantErr: "invalid file pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			limit := semaphore.NewWeighted(3)

			got := new(analyzer.AnalysisResult)
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
				FilePatterns:      tt.args.filePatterns,
				DisabledAnalyzers: tt.args.disabledAnalyzers,
			})
			if err != nil && tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			info, err := os.Stat(tt.args.testFilePath)
			require.NoError(t, err)

			ctx := context.Background()
			err = a.AnalyzeFile(ctx, &wg, limit, got, "", tt.args.filePath, info,
				func() (dio.ReadSeekCloserAt, error) {
					if tt.args.testFilePath == "testdata/error" {
						return nil, xerrors.New("error")
					} else if tt.args.testFilePath == "testdata/no-permission" {
						os.Chmod(tt.args.testFilePath, 0000)
						t.Cleanup(func() {
							os.Chmod(tt.args.testFilePath, 0644)
						})
					}
					return os.Open(tt.args.testFilePath)
				},
				nil, analyzer.AnalysisOptions{},
			)

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
		config            *v1.ConfigFile
		disabledAnalyzers []analyzer.Type
		filePatterns      []string
	}
	tests := []struct {
		name string
		args args
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				config: &v1.ConfigFile{
					OS: "linux",
				},
			},
			want: &analyzer.AnalysisResult{
				Files: map[types.HandlerType][]types.File{},
				PackageInfos: []types.PackageInfo{
					{
						Packages: []types.Package{
							{
								Name:    "musl",
								Version: "1.1.24-r2",
							},
						},
					},
				},
			},
		},
		{
			name: "non-target OS",
			args: args{
				targetOS: types.OS{
					Family: "debian",
					Name:   "9.2",
				},
				config: &v1.ConfigFile{
					OS: "linux",
				},
			},
			want: analyzer.NewAnalysisResult(),
		},
		{
			name: "Analyze returns an error",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
			},
			want: analyzer.NewAnalysisResult(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
				FilePatterns:      tt.args.filePatterns,
				DisabledAnalyzers: tt.args.disabledAnalyzers,
			})
			require.NoError(t, err)
			got := a.AnalyzeImageConfig(tt.args.targetOS, tt.args.config)
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
				"apk-repo": 1,
				"apk":      2,
				"bundler":  1,
				"ubuntu":   1,
			},
		},
		{
			name: "disable analyzers",
			disabled: []analyzer.Type{
				analyzer.TypeAlpine,
				analyzer.TypeApkRepo,
				analyzer.TypeUbuntu,
			},
			want: map[string]int{
				"apk":     2,
				"bundler": 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
				DisabledAnalyzers: tt.disabled,
			})
			require.NoError(t, err)
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
			name: "disable analyzers",
			disabled: []analyzer.Type{
				analyzer.TypeAlpine,
				analyzer.TypeApkCommand,
			},
			want: map[string]int{
				"test": 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
				DisabledAnalyzers: tt.disabled,
			})
			require.NoError(t, err)
			got := a.ImageConfigAnalyzerVersions()
			assert.Equal(t, tt.want, got)
		})
	}
}
