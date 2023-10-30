package pub

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pubSpecLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name        string
		dir         string
		pubCacheEnv string
		want        *analyzer.AnalysisResult
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			// Supports only absolute paths for `rootUri` in package_config.json
			// But for this test this field was changed
			name:        "happy path with cache",
			dir:         "testdata/happy",
			pubCacheEnv: "testdata/happy/cache",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pub,
						FilePath: "pubspec.lock",
						Libraries: types.Packages{
							{
								ID:       "collection@1.17.0",
								Name:     "collection",
								Version:  "1.17.0",
								Indirect: true,
							},
							{
								ID:      "crypto@3.0.3",
								Name:    "crypto",
								Version: "3.0.3",
								DependsOn: []string{
									"typed_data@1.3.2",
								},
							},
							{
								ID:      "meta@1.11.0",
								Name:    "meta",
								Version: "1.11.0",
							},
							{
								ID:       "typed_data@1.3.2",
								Name:     "typed_data",
								Version:  "1.3.2",
								Indirect: true,
								DependsOn: []string{
									"collection@1.17.0",
								},
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:        "happy path without cache",
			dir:         "testdata/happy",
			pubCacheEnv: "testdata/happy/empty",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pub,
						FilePath: "pubspec.lock",
						Libraries: types.Packages{
							{
								ID:       "collection@1.17.0",
								Name:     "collection",
								Version:  "1.17.0",
								Indirect: true,
							},
							{
								ID:      "crypto@3.0.3",
								Name:    "crypto",
								Version: "3.0.3",
							},
							{
								ID:      "meta@1.11.0",
								Name:    "meta",
								Version: "1.11.0",
							},
							{
								ID:       "typed_data@1.3.2",
								Name:     "typed_data",
								Version:  "1.3.2",
								Indirect: true,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "empty file",
			dir:     "testdata/empty",
			want:    &analyzer.AnalysisResult{},
			wantErr: assert.NoError,
		},
		{
			name:    "broken file",
			dir:     "testdata/broken",
			want:    &analyzer.AnalysisResult{},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PUB_CACHE", tt.pubCacheEnv)
			a, err := newPubSpecLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pubSpecLockAnalyzer_cacheDir(t *testing.T) {
	tests := []struct {
		name            string
		pubCacheEnv     string
		localAppDataEnv string
		windowsTest     bool
		wantDir         string
	}{
		{
			name:    "default cache dir for Linux/MacOS",
			wantDir: "/root/.pub_cache",
		},
		{
			name:        "default cache dir Windows",
			windowsTest: true,
			wantDir:     "C:\\Users\\User\\AppData\\Local\\Pub\\Cache",
		},
		{
			name:        "PUB_CACHE is used",
			pubCacheEnv: "/root/cache",
			wantDir:     "/root/cache",
		},
		{
			name:        "PUB_CACHE is used in Windows",
			pubCacheEnv: "C:\\Cache",
			windowsTest: true,
			wantDir:     "C:\\Cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				if !tt.windowsTest {
					t.Skipf("This test is not used for %s", runtime.GOOS)
				}
				t.Setenv("LOCALAPPDATA", "C:\\Users\\User\\AppData\\Local")
			} else {
				if tt.windowsTest {
					t.Skipf("This test is not used for %s", runtime.GOOS)
				}
				t.Setenv("HOME", "/root")
			}

			t.Setenv("PUB_CACHE", tt.pubCacheEnv)

			dir := cacheDir()
			assert.Equal(t, tt.wantDir, dir)
		})
	}
}

func Test_pubSpecLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "pubspec.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pubSpecLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
