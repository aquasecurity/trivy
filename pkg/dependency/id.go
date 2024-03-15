package dependency

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ID returns a unique ID for the given library.
// The package ID is used to construct the dependency graph.
// The separator is different for each language type.
func ID(ltype types.LangType, name, version string) string {
	if version == "" {
		return name
	}

	sep := "@"
	switch ltype {
	case types.Conan:
		sep = "/"
	case types.GoModule, types.GoBinary:
		// Return a module ID according the Go way.
		// Format: <module_name>@v<module_version>
		// e.g. github.com/aquasecurity/go-dep-parser@v0.0.0-20230130190635-5e31092b0621
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case types.Jar, types.Pom, types.Gradle:
		sep = ":"
	}
	return name + sep + version
}
