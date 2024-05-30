package pip

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func Test_pipAnalyzer_Analyze(t *testing.T) {
	resultWithLicenses := &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.Pip,
				FilePath: "requirements.txt",
				Packages: types.Packages{
					{
						Name:    "click",
						Version: "8.0.0",
						Locations: []types.Location{
							{
								StartLine: 1,
								EndLine:   1,
							},
						},
						Licenses: []string{
							"BSD License",
						},
					},
					{
						Name:    "Flask",
						Version: "2.0.0",
						Locations: []types.Location{
							{
								StartLine: 2,
								EndLine:   2,
							},
						},
						Licenses: []string{
							"BSD License",
						},
					},
					{
						Name:    "itsdangerous",
						Version: "2.0.0",
						Locations: []types.Location{
							{
								StartLine: 3,
								EndLine:   3,
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name          string
		dir           string
		venv          string
		pythonExecDir string
		want          *analyzer.AnalysisResult
		wantErr       string
	}{
		{
			name:          "happy path with licenses from venv",
			dir:           filepath.Join("testdata", "happy"),
			venv:          filepath.Join("testdata", "libs", "python-dir"),
			pythonExecDir: filepath.Join("testdata", "libs", "python-dir", "bin"),
			want:          resultWithLicenses,
		},
		{
			name:          "happy path with licenses from python dir",
			dir:           filepath.Join("testdata", "happy"),
			pythonExecDir: filepath.Join("testdata", "libs", "python-dir", "bin"),
			want:          resultWithLicenses,
		},
		{
			name:          "happy path with licenses from common dir",
			dir:           filepath.Join("testdata", "happy"),
			pythonExecDir: filepath.Join("testdata", "libs", "common-dir", "foo", "bar"),
			want:          resultWithLicenses,
		},
		{
			name: "happy path without licenses",
			dir:  filepath.Join("testdata", "happy"),
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pip,
						FilePath: "requirements.txt",
						Packages: types.Packages{
							{
								Name:    "click",
								Version: "8.0.0",
								Locations: []types.Location{
									{
										StartLine: 1,
										EndLine:   1,
									},
								},
							},
							{
								Name:    "Flask",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 2,
										EndLine:   2,
									},
								},
							},
							{
								Name:    "itsdangerous",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 3,
										EndLine:   3,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with not related filename",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.venv != "" {
				t.Setenv("VIRTUAL_ENV", tt.venv)
			}

			var newPATH string
			if tt.pythonExecDir != "" {
				err := os.MkdirAll(tt.pythonExecDir, os.ModePerm)
				require.NoError(t, err)
				defer func() {
					if strings.HasSuffix(tt.pythonExecDir, "bar") { // for `happy path with licenses from common dir` test
						tt.pythonExecDir = filepath.Dir(tt.pythonExecDir)
					}
					err = os.RemoveAll(tt.pythonExecDir)
					require.NoError(t, err)
				}()

				pythonExecFileName := "python"
				if runtime.GOOS == "windows" {
					pythonExecFileName = "python.exe"
				}
				// create temp python3 Executable
				err = os.WriteFile(filepath.Join(tt.pythonExecDir, pythonExecFileName), nil, 0755)
				require.NoError(t, err)

				newPATH, err = filepath.Abs(tt.pythonExecDir)
				require.NoError(t, err)

			}
			t.Setenv("PATH", newPATH)

			a, err := newPipLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pipAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/requirements.txt",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pipLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pythonExecutablePath(t *testing.T) {
	tests := []struct {
		name     string
		execName string
		wantErr  string
	}{
		{
			name:     "happy path with `python` filename",
			execName: "python",
		},
		{
			name:     "happy path with `python3` filename",
			execName: "python3",
		},
		{
			name:     "happy path with `python2` filename",
			execName: "python2",
		},
		{
			name:     "sad path. Python executable not found",
			execName: "python-wrong",
			wantErr:  "unable to find path to Python executable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			binDir := filepath.Join(tmpDir, "bin")
			err := os.MkdirAll(binDir, os.ModePerm)
			require.NoError(t, err)

			if runtime.GOOS == "windows" {
				tt.execName += ".exe"
			}
			err = os.WriteFile(filepath.Join(binDir, tt.execName), nil, 0755)
			require.NoError(t, err)

			t.Setenv("PATH", binDir)

			path, err := pythonExecutablePath()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.execName, filepath.Base(path))
		})
	}
}

func Test_sortPythonDirs(t *testing.T) {
	dirs := []string{
		"wrong",
		"wrong2.7",
		"python3.11",
		"python3.10",
		"python2.7",
		"python3.9",
		"python3",
		"python2",
		"pythonBadVer",
	}
	wantDirs := []string{
		"python2",
		"python2.7",
		"python3",
		"python3.9",
		"python3.10",
		"python3.11",
	}

	tmp := t.TempDir()
	for _, dir := range dirs {
		err := os.Mkdir(filepath.Join(tmp, dir), os.ModePerm)
		require.NoError(t, err)
	}

	tmpDir, err := os.ReadDir(tmp)
	require.NoError(t, err)

	a := pipLibraryAnalyzer{
		logger: log.WithPrefix("pip"),
	}
	got := a.sortPythonDirs(tmpDir)
	require.Equal(t, wantDirs, got)
}
