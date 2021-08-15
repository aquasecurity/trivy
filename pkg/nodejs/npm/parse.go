package npm

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type LockFile struct {
	Dependencies map[string]Dependency
}
type Dependency struct {
	Version      string
	Dev          bool
	Dependencies map[string]Dependency
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	libs := parse(lockFile.Dependencies)
	return unique(libs), nil
}

func parse(dependencies map[string]Dependency) []types.Library {
	var libs []types.Library
	for pkgName, dependency := range dependencies {
		if dependency.Dev {
			continue
		}

		libs = append(libs, types.Library{
			Name:    pkgName,
			Version: dependency.Version,
		})

		if dependency.Dependencies != nil {
			// Recursion
			libs = append(libs, parse(dependency.Dependencies)...)
		}
	}
	return libs
}

func unique(libs []types.Library) []types.Library {
	var uniqLibs []types.Library
	unique := map[types.Library]struct{}{}
	for _, lib := range libs {
		if _, ok := unique[lib]; !ok {
			unique[lib] = struct{}{}
			uniqLibs = append(uniqLibs, lib)
		}
	}
	return uniqLibs
}
