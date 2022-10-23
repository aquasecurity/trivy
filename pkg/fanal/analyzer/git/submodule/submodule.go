package submodule

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/go-git/go-git/v5"
	giturls "github.com/whilp/git-urls"
	"golang.org/x/xerrors"
)

func init() {
	analyzer.RegisterAnalyzer(&gitSubmoduleAnalyzer{})
}

const version = 1

type gitSubmoduleAnalyzer struct{}

func (a gitSubmoduleAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	libs, deps, err := parseGitmodules(input.Dir)
	if err != nil {
		return nil, xerrors.Errorf("git repo parse error: %w", err)
	}

	return language.ToAnalysisResult(types.GitSubmodule, input.FilePath, "", libs, deps), nil
}

func (a gitSubmoduleAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return fileInfo.Name() == types.GitModules
}

func (a gitSubmoduleAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGitSubmodule
}

func (a gitSubmoduleAnalyzer) Version() int {
	return version
}

func parseGitmodules(inputDir string) ([]godeptypes.Library, []godeptypes.Dependency, error) {
	repo, err := git.PlainOpen(inputDir)
	if err != nil {
		return nil, nil, err
	}

	w, err := repo.Worktree()
	if err != nil {
		return nil, nil, err
	}

	submodules, err := w.Submodules()
	if err != nil {
		return nil, nil, err
	}

	libs, _ := parseSubmodules(repo, &submodules)
	return libs, nil, nil
}

func parseSubmodules(repo *git.Repository, submodules *git.Submodules) ([]godeptypes.Library, []godeptypes.Dependency) {
	var libs []godeptypes.Library
	var name *url.URL

	for _, submodule := range *submodules {
		remote := submodule.Config().URL

		if strings.HasPrefix(remote, "../") {
			// resolve relative URLs via root remote
			rootRemote, err := getRemoteUrl(repo)
			if err != nil {
				return nil, nil
			}

			baseUrl, _ := giturls.Parse(fmt.Sprintf("%s/", rootRemote))
			name, _ = baseUrl.Parse(remote)
		} else {
			name, _ = giturls.Parse(remote)
		}

		status, _ := submodule.Status()
		version := status.Expected.String()

		libs = append(libs, godeptypes.Library{
			Name:    name.String(),
			Version: version,
		})
	}

	return libs, nil
}

func getRemoteUrl(repo *git.Repository) (string, error) {
	remote, err := repo.Remote("origin")
	if err != nil {
		return "", err
	}

	return remote.Config().URLs[0], nil
}
