package dependency

import (
	"fmt"
	"strings"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
	// cf. https://github.com/dotnet/sdk/blob/529132850841a6bcfce96799262ce688e3851875/documentation/specs/runtime-configuration-file.md#targets-section-depsjson
	case types.Conan, types.DotNetCore:
		sep = "/"
	case types.GoModule, types.GoBinary:
		// Return a module ID according the Go way.
		// Format: <module_name>@v<module_version>
		// e.g. github.com/aquasecurity/go-dep-parser@v0.0.0-20230130190635-5e31092b0621
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case types.Jar, types.Pom, types.Gradle, types.Sbt:
		sep = ":"
	}
	return name + sep + version
}

// UID calculates the hash of the package for the unique ID
func UID(filePath string, pkg types.Package) string {
	if pkg.Identifier.UID != "" {
		return pkg.Identifier.UID
	}
	v := map[string]any{
		"filePath": filePath, // To differentiate the hash of the same package but different file path
		"pkg":      pkg,
	}
	hash, err := hashstructure.Hash(v, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
	})
	if err != nil {
		log.Warn("Failed to calculate the package hash", log.String("pkg", pkg.Name), log.Err(err))
	}
	return fmt.Sprintf("%x", hash)
}
