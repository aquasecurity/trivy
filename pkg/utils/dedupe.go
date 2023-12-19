package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/types"

	"github.com/samber/lo"
)

func dedupeNodePackages(result types.Result, lockFilePackages map[string]ftypes.Package) types.Result {
	for j, pkg := range result.Packages {
		if pkg.ID == "" || pkg.FilePath == "" {
			continue
		}

		nodeAppDirInfo := NodeAppDirInfo(pkg.FilePath)
		if !nodeAppDirInfo.IsNodeAppDir {
			continue
		}

		key := nodeAppDirInfo.GetPackageKey(pkg)
		if lPkg, ok := lockFilePackages[key]; ok {
			pkg.Indirect = lPkg.Indirect
			pkg.RootDependencies = lPkg.RootDependencies
			pkg.DependsOn = lPkg.DependsOn
			pkg.NodeDedupeMatchFound = true

			result.Packages[j] = pkg
		}

	}
	return result
}

func dedupePHPPackages(result types.Result, reqDevPHPPackages, reqPHPPackages map[string]struct{}) types.Result {
	for j, pkg := range result.Packages {
		if pkg.Dev {
			if _, ok := reqDevPHPPackages[pkg.Name]; !ok {
				pkg.Indirect = true
			}
		} else {
			if _, ok := reqPHPPackages[pkg.Name]; !ok {
				pkg.Indirect = true
			}
		}

		result.Packages[j] = pkg
	}

	return result
}

type DedupeFilter struct {
	NodeLockFilePackages map[string]ftypes.Package
	ReqDevPHPPackages    map[string]struct{}
	ReqPHPPackages       map[string]struct{}
}

func DedupePackages(filter DedupeFilter, results []types.Result) []types.Result {
	isFilterRequired := false

	// Resource deduplication for Node.js
	for i, result := range results {
		if result.Target == "Node.js" && len(filter.NodeLockFilePackages) > 0 {
			isFilterRequired = true
			results[i] = dedupeNodePackages(result, filter.NodeLockFilePackages)
		}

		if result.Type == ftypes.ComposerInstalled {
			if len(filter.ReqDevPHPPackages) > 0 || len(filter.ReqPHPPackages) > 0 {
				isFilterRequired = true
				results[i] = dedupePHPPackages(result, filter.ReqDevPHPPackages, filter.ReqPHPPackages)
			}
		}
	}

	// Filter results
	if isFilterRequired {
		results = lo.Filter(results, func(r types.Result, i int) bool {
			return lo.IndexOf(ftypes.DedupeFilterTypes, r.Type) == -1
		})
	}

	return results
}

type nodeAppDirInfo struct {
	Path           string
	FileName       string
	AppDir         string
	IsNodeAppDir   bool
	IsNodeLockFile bool
	IsFileinAppDir bool
}

func NodeAppDirInfo(path string) nodeAppDirInfo {
	fileName := filepath.Base(path)
	isNodeAppDir := false
	isNodeLockFile := false
	isFileinAppDir := false

	if fileName == ftypes.NpmPkg {
		isNodeAppDir = true
	} else if lo.IndexOf(ftypes.NodeLockFiles, fileName) != -1 {
		isNodeAppDir = true
		isNodeLockFile = true

	} else {
		return nodeAppDirInfo{Path: path}
	}

	appDir := strings.Split(filepath.Dir(path)+"/", "node_modules")[0]

	// When path is empty filepath.Dir will return "."
	if appDir == "." {
		appDir = ""
	}

	if appDir+fileName == path {
		isFileinAppDir = true
	}

	return nodeAppDirInfo{
		Path:           path,
		FileName:       fileName,
		AppDir:         appDir,
		IsNodeAppDir:   isNodeAppDir,
		IsNodeLockFile: isNodeLockFile,
		IsFileinAppDir: isFileinAppDir,
	}
}

func (n nodeAppDirInfo) GetPackageKey(pkg ftypes.Package) string {
	return fmt.Sprintf("%s:%s", n.AppDir, pkg.ID)
}
