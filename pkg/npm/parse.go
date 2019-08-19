package npm

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
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
		return nil, err
	}

	unique := map[string]struct{}{}
	var libs []types.Library
	for pkgName, dependency := range lockFile.Dependencies {
		dependencies := dependency.Dependencies
		if dependencies == nil {
			dependencies = map[string]Dependency{}
		}
		dependencies[pkgName] = dependency

		for pkgName, dependency := range dependencies {
			if dependency.Dev {
				continue
			}
			symbol := fmt.Sprintf("%s@%s", pkgName, dependency.Version)
			if _, ok := unique[symbol]; ok {
				continue
			}
			libs = append(libs, types.Library{
				Name:    pkgName,
				Version: dependency.Version,
			})
			unique[symbol] = struct{}{}
		}
	}
	return libs, nil
}
