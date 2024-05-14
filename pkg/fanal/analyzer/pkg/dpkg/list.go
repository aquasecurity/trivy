package dpkg

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(newDpkgListAnalyzer())
}

const (
	infoDir             = "var/lib/dpkg/info/"
	listAnalyzerVersion = 1
)

type dpkgListAnalyzer struct {
	logger *log.Logger
}

func newDpkgListAnalyzer() *dpkgListAnalyzer {
	return &dpkgListAnalyzer{
		logger: log.WithPrefix("dpkg-list"),
	}
}

func (a dpkgListAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	systemFiles, err := a.parseDpkgInfoList(scanner)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse dpkg info: %w", err)
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: []types.Package{
					{
						Name:           strings.TrimSuffix(filepath.Base(input.FilePath), ".list"),
						InstalledFiles: systemFiles,
					},
				},
			},
		},
		SystemInstalledFiles: systemFiles,
	}, nil
}

// parseDpkgInfoList parses /var/lib/dpkg/info/*.list
func (a dpkgListAnalyzer) parseDpkgInfoList(scanner *bufio.Scanner) ([]string, error) {
	var (
		allLines       []string
		installedFiles []string
		previous       string
	)

	for scanner.Scan() {
		current := scanner.Text()
		if current == "/." {
			continue
		}
		allLines = append(allLines, current)
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	// Add the file if it is not directory.
	// e.g.
	//  /usr/sbin
	//  /usr/sbin/tarcat
	//
	// In the above case, we should take only /usr/sbin/tarcat since /usr/sbin is a directory
	// sort first,see here:https://github.com/aquasecurity/trivy/discussions/6543
	sort.Strings(allLines)
	for _, current := range allLines {
		if !strings.HasPrefix(current, previous+"/") {
			installedFiles = append(installedFiles, previous)
		}
		previous = current
	}

	// Add the last file
	if previous != "" && !strings.HasSuffix(previous, "/") {
		installedFiles = append(installedFiles, previous)
	}

	return installedFiles, nil
}

func (a dpkgListAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, fileName := filepath.Split(filePath)
	if dir != infoDir {
		return false
	}
	return filepath.Ext(fileName) == ".list"
}

func (a dpkgListAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDpkgSystemFiles
}

func (a dpkgListAnalyzer) Version() int {
	return listAnalyzerVersion
}
