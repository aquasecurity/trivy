package submodule

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func Test_gitSubmoduleAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "https-url",
			filePath: "testdata/https-url.gitmodules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GitSubmodule,
						FilePath: types.GitModules,
						Libraries: []types.Package{
							{
								Name:    "https://github.com/org/repository.git",
								Version: "ca82a6dff817ec66f44342007202690a93763949",
							},
						},
					},
				},
			},
		},
		{
			name:     "git-url",
			filePath: "testdata/git-url.gitmodules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GitSubmodule,
						FilePath: types.GitModules,
						Libraries: []types.Package{
							{
								Name:    "ssh://git@github.com/org/repository.git",
								Version: "ca82a6dff817ec66f44342007202690a93763949",
							},
						},
					},
				},
			},
		},
		{
			name:     "ssh-url",
			filePath: "testdata/ssh-url.gitmodules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GitSubmodule,
						FilePath: types.GitModules,
						Libraries: []types.Package{
							{
								Name:    "ssh://git@github.com/org/repository.git",
								Version: "ca82a6dff817ec66f44342007202690a93763949",
							},
						},
					},
				},
			},
		},
		{
			name:     "relative-url",
			filePath: "testdata/relative-url.gitmodules",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GitSubmodule,
						FilePath: types.GitModules,
						Libraries: []types.Package{
							{
								Name:    "https://github.com/org/repository.git",
								Version: "ca82a6dff817ec66f44342007202690a93763949",
							},
						},
					},
				},
			},
		},
		{
			name:     "missing-submodule",
			filePath: "testdata/missing-submodule.gitmodules",
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentDir, err := os.Getwd()
			require.NoError(t, err)

			dir := t.TempDir()
			destFilePath := filepath.Join(dir, types.GitModules)

			_, err = utils.CopyFile(tt.filePath, destFilePath)
			require.NoError(t, err)

			err = initRepoWithSubmodules(dir)
			require.NoError(t, err)

			err = os.Chdir(dir)
			require.NoError(t, err)
			defer os.Chdir(currentDir)

			a := gitSubmoduleAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				Dir:      dir,
				FilePath: types.GitModules,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func initRepoWithSubmodules(dir string) error {
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		return err
	}

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/org/repository.git"},
	})
	if err != nil {
		return err
	}

	updateIndexCmd := exec.Command(
		"git",
		"update-index",
		"--add",
		"--cacheinfo",
		"160000",
		"ca82a6dff817ec66f44342007202690a93763949",
		"submodule",
	)
	updateIndexCmd.Dir = dir
	updateIndexCmd.Run()
	if err != nil {
		return err
	}

	return nil
}
