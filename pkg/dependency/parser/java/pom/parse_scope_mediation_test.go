package pom_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/pom"
)

// A `test`-scoped dependency of the root POM is declared at depth 1, so Maven's
// nearest-wins mediation resolves that group:artifact to its version even though
// the scope is `test`. The single resolved copy is then test-scoped, which means
// it is not on the compile/runtime classpath at all.
//
// Before this was handled, the declaration was dropped before mediation ran, so
// the depth-2 transitive version won instead and was reported as a component
// that the build never resolves.
//
// See https://github.com/aquasecurity/trivy/issues/7844
func TestPom_Parse_TestScopeDecidesVersion(t *testing.T) {
	inputFile := filepath.Join("testdata", "test-scope-decides-version", "pom.xml")

	f, err := os.Open(inputFile)
	require.NoError(t, err)
	defer f.Close()

	ts := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("testdata", "repository"))))
	defer ts.Close()

	p := pom.NewParser(inputFile, pom.WithDefaultRepo(ts.URL, true, true))

	gotPkgs, _, err := p.Parse(t.Context(), f)
	require.NoError(t, err)

	var names []string
	versions := make(map[string]string)
	for _, pkg := range gotPkgs {
		names = append(names, pkg.Name)
		versions[pkg.Name] = pkg.Version
	}

	// The test-scoped declaration wins mediation, so no copy of example-api is
	// on the compile/runtime classpath.
	assert.NotContains(t, names, "org.example:example-api",
		"a test-scoped declaration at depth 1 wins mediation, so example-api must not be reported")

	// In particular the transitive 2.0.0 must not be reported: it loses
	// mediation to the depth-1 declaration and is never resolved by Maven.
	assert.NotEqual(t, "2.0.0", versions["org.example:example-api"])

	// The compile-scoped dependency that pulled it in is unaffected.
	assert.Contains(t, names, "org.example:example-dependency")
	assert.Equal(t, "1.2.3", versions["org.example:example-dependency"])
}
