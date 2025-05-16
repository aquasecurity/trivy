package swift

import (
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	Object  Object `json:"object"`
	Pins    []Pin  `json:"pins"`
	Version int    `json:"version"`
}

type Object struct {
	Pins []Pin `json:"pins"`
}

type Pin struct {
	Package       string `json:"package"`
	RepositoryURL string `json:"repositoryURL"` // Package.revision v1
	Loc           string `json:"location"`      // Package.revision v2
	State         State  `json:"state"`
	xjson.Location
}

type State struct {
	Branch   string `json:"branch"`
	Revision string `json:"revision"`
	Version  string `json:"version"`
}
