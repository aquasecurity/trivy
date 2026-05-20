package packagejson

import (
	"encoding/json"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              License           `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Workspaces           any               `json:"workspaces"`
}

type Package struct {
	ftypes.Package
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	DevDependencies      map[string]string
	Workspaces           []string
}

// License represents the npm "license" field, which historically
// supports several shapes:
//   - string:                 "MIT"
//   - object (legacy):        {"type": "MIT", "url": "..."}
//   - array of objects (legacy): [{"type": "MIT", ...}, {"type": "Apache-2.0", ...}]
//
// See https://docs.npmjs.com/cli/v11/configuring-npm/package-json#license
type License struct {
	names []string
}

type licenseObject struct {
	Type string `json:"type"`
}

func (l *License) UnmarshalJSON(data []byte) error {
	// "MIT"
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "" {
			l.names = []string{s}
		}
		return nil
	}

	// {"type": "MIT", ...}
	var obj licenseObject
	if err := json.Unmarshal(data, &obj); err == nil && obj.Type != "" {
		l.names = []string{obj.Type}
		return nil
	}

	// [{"type": "MIT", ...}, ...]
	var arr []licenseObject
	if err := json.Unmarshal(data, &arr); err == nil {
		for _, o := range arr {
			if o.Type != "" {
				l.names = append(l.names, o.Type)
			}
		}
		return nil
	}

	// Unknown shape — return empty list instead of failing the whole file.
	return nil
}

// Names returns the list of license names extracted from the field.
func (l License) Names() []string {
	return l.names
}
