package yarn

import (
	"encoding/json"
	"io"
)

type PackageJson struct {
	Dependencies map[string]string `json:"dependencies"`
}

type PackageJsonParser struct {
}

func NewPackageJsonParser() PackageJsonParser {
	return PackageJsonParser{}
}

func (p PackageJsonParser) Parse(r io.Reader) (PackageJson, error) {
	packageJson := PackageJson{}
	err := json.NewDecoder(r).Decode(&packageJson)
	if err != nil {
		return PackageJson{}, err
	}
	return packageJson, nil
}
