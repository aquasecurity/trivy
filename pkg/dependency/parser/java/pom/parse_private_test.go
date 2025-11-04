package pom

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// TestPom_Parse_Remote_Repos checks that we get dependencies from the correct repositories.
// For this, three servers are created:
// a root server and two servers with dependencies — example-api and example-api2.
// These dependencies have different licenses on the two servers (for verification purposes).
func TestPom_Parse_Remote_Repos(t *testing.T) {
	// Set up the first mock Maven repository with example-api + example-api2 packages.
	// These packages use "The Apache Software License, Version 2.0" license.
	repo1 := t.TempDir()
	testutil.CopyDir(t, filepath.Join("testdata", "repository"), repo1)
	ts1 := httptest.NewServer(http.FileServer(http.Dir(repo1)))
	defer ts1.Close()

	// Set up the second mock Maven repository with example-api + example-api2 packages.
	// These packages use "Custom License from custom repo" license.
	repo2 := t.TempDir()
	testutil.CopyDir(t, filepath.Join("testdata", "repository-for-settings-repo"), repo2)
	ts2 := httptest.NewServer(http.FileServer(http.Dir(repo2)))
	defer ts2.Close()

	rootRepo := t.TempDir()

	// Prepare dependency artifacts in the root repo and rewrite their POMs to
	// point to the corresponding remote repositories (ts1 and ts2).
	dependencyDir := filepath.Join("org", "example", "example-dependency", "5.0.0")
	testutil.CopyDir(t, filepath.Join("testdata", "repository", dependencyDir), filepath.Join(rootRepo, dependencyDir))
	addRepoURLToPOM(t, filepath.Join(rootRepo, dependencyDir, "example-dependency-5.0.0.pom"), ts1.URL)

	dependency2Dir := filepath.Join("org", "example", "example-dependency2", "5.0.0")
	testutil.CopyDir(t, filepath.Join("testdata", "repository", dependency2Dir), filepath.Join(rootRepo, dependency2Dir))
	addRepoURLToPOM(t, filepath.Join(rootRepo, dependency2Dir, "example-dependency2-5.0.0.pom"), ts2.URL)

	tsRoot := httptest.NewServer(http.FileServer(http.Dir(rootRepo)))
	defer tsRoot.Close()

	// Parse the POM that declares dependencies located in different repos.
	testFile := filepath.Join("testdata", "different-repos-for-different-poms", "pom.xml")
	parser := NewParser(testFile, WithDefaultRepo(tsRoot.URL, true, true))

	f, err := os.Open(testFile)
	require.NoError(t, err)
	defer f.Close()

	pkgs, _, err := parser.Parse(t.Context(), f)
	require.NoError(t, err)

	pkgMap := lo.SliceToMap(pkgs, func(p ftypes.Package) (string, ftypes.Package) {
		return p.ID, p
	})

	// Expected packages and their licenses, each coming from a different repo.
	wantPkgs := map[string]string{
		"org.example:example-api:1.7.30": "The Apache Software License, Version 2.0",
		"org.example:example-api2:1.0.0": "Custom License from custom repo",
	}

	// Package verification by matching licenses.
	for id, license := range wantPkgs {
		pkg, ok := pkgMap[id]
		if !ok {
			t.Errorf("expected package %s not found", id)
			return
		}
		if pkg.Licenses == nil || len(pkg.Licenses) == 0 {
			t.Errorf("expected license for package %s, but got none", id)
			return
		}
		if pkg.Licenses[0] != license {
			t.Errorf("expected license %s for package %s, but got %s", license, id, pkg.Licenses[0])
			return
		}
	}
}

func addRepoURLToPOM(t *testing.T, filePath, repoURL string) {
	t.Helper()
	b, err := os.ReadFile(filePath)
	require.NoError(t, err)

	if repoURL == "" {
		return
	}

	// Replace the first <url>...</url> occurrence inside the POM with the provided repo URL.
	// These test POMs contain a single <repositories><repository><url>...</url>...</repository></repositories> block.
	re := regexp.MustCompile(`<url>.*?</url>`)
	updated := re.ReplaceAllString(string(b), `<url>`+repoURL+`</url>`)

	require.NoError(t, os.WriteFile(filePath, []byte(updated), 0o644))
}
