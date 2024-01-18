package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"

	"github.com/samber/lo"
)

func dedupeNodePackages(app ftypes.Application, lockFilePackages map[string]ftypes.Package) ftypes.Application {
	for j, pkg := range app.Libraries {
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

			// handle splitting of indirect & direct package
			// as we have the transitive info from the lockFilePackages
			if !pkg.Indirect && len(pkg.RootDependencies) > 0 {
				indirectPkg := pkg
				indirectPkg.Indirect = true
				indirectPkg.RootDependencies = pkg.RootDependencies

				app.Libraries = append(app.Libraries, indirectPkg)

				// remove rootdeps from direct dep
				pkg.RootDependencies = []string{}
			}

			// update app
			app.Libraries[j] = pkg
		}

	}
	return app
}

func dedupePHPPackages(app ftypes.Application, reqDevPHPPackages, reqPHPPackages map[string]struct{}) ftypes.Application {
	for j, pkg := range app.Libraries {
		if pkg.Dev {
			if _, ok := reqDevPHPPackages[pkg.Name]; !ok {
				pkg.Indirect = true
			}
		} else {
			if _, ok := reqPHPPackages[pkg.Name]; !ok {
				pkg.Indirect = true
			}
		}

		app.Libraries[j] = pkg
	}

	return app
}

type DedupeFilter struct {
	NodeLockFilePackages map[string]ftypes.Package
	ReqDevPHPPackages    map[string]struct{}
	ReqPHPPackages       map[string]struct{}
}

func DedupePackages(filter DedupeFilter, apps []ftypes.Application) []ftypes.Application {
	isFilterRequired := false

	// Resource deduplication for Node.js
	for i, app := range apps {
		if app.Type == ftypes.NodePkg && len(filter.NodeLockFilePackages) > 0 {
			isFilterRequired = true
			apps[i] = dedupeNodePackages(app, filter.NodeLockFilePackages)
		}

		if app.Type == ftypes.ComposerInstalled {
			if len(filter.ReqDevPHPPackages) > 0 || len(filter.ReqPHPPackages) > 0 {
				isFilterRequired = true
				apps[i] = dedupePHPPackages(app, filter.ReqDevPHPPackages, filter.ReqPHPPackages)
			}
		}
	}

	// Filter apps
	if isFilterRequired {
		apps = lo.Filter(apps, func(r ftypes.Application, i int) bool {
			return lo.IndexOf(ftypes.DedupeFilterTypes, r.Type) == -1
		})
	}

	return apps
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
