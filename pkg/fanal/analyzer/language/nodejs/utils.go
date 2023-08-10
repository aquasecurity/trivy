package nodejs

import (
	"io/fs"
	"path"
	"strings"
)

func IsNodeModulesPkgJson(filePath string) bool {
	return IsPkgRootFile(filePath) && strings.HasSuffix(filePath, "package.json")
}

func IsNodeModulesPkg(filePath string, _ fs.DirEntry) bool {
	return IsNodeModulesPkgJson(filePath)
}

func IsPkgRootFile(filePath string) bool {
	dirs := strings.Split(path.Dir(filePath), "/")
	nodeModulesIdx := len(dirs) - 2
	// the scope starts with "@" https://docs.npmjs.com/cli/v9/using-npm/scope
	if len(dirs) > 2 && strings.HasPrefix(dirs[len(dirs)-2], "@") {
		nodeModulesIdx -= 1
	}
	// The file path to package.json - */node_modules/<package_name>/package.json
	// or */node_modules/@<scope_name>/<package_name>/package.json
	return len(dirs) > 1 && dirs[nodeModulesIdx] == "node_modules"
}
