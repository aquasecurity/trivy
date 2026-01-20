package pom

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// mockRepository represents a mock Maven repository
type mockRepository struct {
	name      string // Repository name for identification
	sourceDir string // Source directory in testdata to copy from
}

// artifactInRepo describes an artifact to be placed in the root repository
// with a POM that points to a specific remote repository
type artifactInRepo struct {
	groupID      string // e.g., "org.example"
	artifactID   string // e.g., "example-dependency"
	version      string // e.g., "5.0.0"
	repoRef      string // Reference to repository name (from mockRepository)
	sourceDir    string // Source directory in testdata to copy from
	sourcePomDir string // Optional: if POM is in different location
}

// testCase represents a single test case for remote repository testing
type testCase struct {
	name             string            // Test case name
	rootPomFile      string            // Path to root POM file in testdata
	mockRepos        []mockRepository  // Mock repositories to create
	artifactsInRoot  []artifactInRepo  // Artifacts to place in root repository
	wantPackages     map[string]string // Expected package ID -> license mapping
	wantErr          bool              // Whether error is expected
	matchWithoutHash bool              // Match packages without hash (for multi-module projects)
	rootPomRepoRef   string            // Optional: repository to use for root POM repositories section
}

// TestPom_Parse_Remote_Repos checks that we get dependencies from the correct repositories.
// This test creates multiple mock Maven repositories and verifies that dependencies
// are resolved from the appropriate repository based on the POM configuration.
func TestPom_Parse_Remote_Repos(t *testing.T) {
	tests := []testCase{
		{
			name:        "different repos for different dependencies",
			rootPomFile: filepath.Join("testdata", "different-repos-for-different-poms", "pom.xml"),
			mockRepos: []mockRepository{
				{
					name:      "repo1",
					sourceDir: filepath.Join("testdata", "repository"),
				},
				{
					name:      "repo2",
					sourceDir: filepath.Join("testdata", "repository-for-settings-repo"),
				},
			},
			artifactsInRoot: []artifactInRepo{
				{
					groupID:    "org.example",
					artifactID: "example-dependency",
					version:    "5.0.0",
					repoRef:    "repo1",
					sourceDir:  filepath.Join("testdata", "repository"),
				},
				{
					groupID:    "org.example",
					artifactID: "example-dependency2",
					version:    "5.0.0",
					repoRef:    "repo2",
					sourceDir:  filepath.Join("testdata", "repository"),
				},
			},
			wantPackages: map[string]string{
				"org.example:example-api:1.7.30::2cbe1ca4": "The Apache Software License, Version 2.0",
				"org.example:example-api2:1.0.0::f8958ec7": "Custom License from custom repo",
			},
			matchWithoutHash: false,
		},
		{
			name:        "multi-module with different repos",
			rootPomFile: filepath.Join("testdata", "multi-module-different-repos", "pom.xml"),
			mockRepos: []mockRepository{
				{
					name:      "repo1",
					sourceDir: filepath.Join("testdata", "repository"),
				},
				{
					name:      "repo2",
					sourceDir: filepath.Join("testdata", "repository-for-settings-repo"),
				},
				{
					name:      "repo3",
					sourceDir: filepath.Join("testdata", "repository-for-root-pom"),
				},
			},
			artifactsInRoot: []artifactInRepo{
				{
					groupID:    "org.example",
					artifactID: "example-dependency",
					version:    "5.0.0",
					repoRef:    "repo1",
					sourceDir:  filepath.Join("testdata", "repository"),
				},
				{
					groupID:    "org.example",
					artifactID: "example-dependency2",
					version:    "5.0.0",
					repoRef:    "repo2",
					sourceDir:  filepath.Join("testdata", "repository"),
				},
				{
					groupID:    "org.example",
					artifactID: "example-root-dep",
					version:    "3.0.0",
					repoRef:    "repo3",
					sourceDir:  filepath.Join("testdata", "repository"),
				},
			},
			wantPackages: map[string]string{
				"org.example:example-api:1.7.30": "The Apache Software License, Version 2.0",
				"org.example:example-api2:1.0.0": "Custom License from custom repo",
				"org.example:example-api3:2.0.0": "License from Root POM Repository",
			},
			matchWithoutHash: true,
			rootPomRepoRef:   "repo3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock repositories
			repoURLs := setupMockRepositories(t, tt.mockRepos)

			// Setup root repository with artifacts
			rootRepoURL := setupRootRepository(t, tt.artifactsInRoot, repoURLs)

			// Prepare POM file for testing
			pomFileToParse := preparePomFile(t, tt.rootPomFile, tt.rootPomRepoRef, repoURLs)

			// Parse the POM
			parser := NewParser(pomFileToParse, WithDefaultRepo(rootRepoURL, true, true))
			f, err := os.Open(pomFileToParse)
			require.NoError(t, err)
			defer f.Close()

			pkgs, _, err := parser.Parse(t.Context(), f)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify expected packages
			verifyPackages(t, pkgs, tt.wantPackages, tt.matchWithoutHash)
		})
	}
}

// setupMockRepositories creates mock HTTP repositories and returns their URLs
func setupMockRepositories(t *testing.T, repos []mockRepository) map[string]string {
	t.Helper()
	repoURLs := make(map[string]string)
	for _, repo := range repos {
		repoDir := t.TempDir()
		testutil.CopyDir(t, repo.sourceDir, repoDir)
		ts := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		t.Cleanup(ts.Close)
		repoURLs[repo.name] = ts.URL
	}
	return repoURLs
}

// setupRootRepository creates a root Maven repository with artifacts and returns its URL
func setupRootRepository(t *testing.T, artifacts []artifactInRepo, repoURLs map[string]string) string {
	t.Helper()
	rootRepo := t.TempDir()

	for _, artifact := range artifacts {
		// Convert groupID dots to slashes (e.g., org.example -> org/example)
		artifactPath := filepath.Join(
			filepath.Join(splitGroupID(artifact.groupID)...),
			artifact.artifactID,
			artifact.version,
		)

		// Copy artifact from source
		sourceArtifactPath := filepath.Join(artifact.sourceDir, artifactPath)
		targetArtifactPath := filepath.Join(rootRepo, artifactPath)
		testutil.CopyDir(t, sourceArtifactPath, targetArtifactPath)

		// Update POM to point to the specified repository
		pomFileName := artifact.artifactID + "-" + artifact.version + ".pom"
		pomPath := filepath.Join(targetArtifactPath, pomFileName)
		repoURL := repoURLs[artifact.repoRef]
		addRepoURLToPOM(t, pomPath, repoURL)
	}

	// Start root repository server
	ts := httptest.NewServer(http.FileServer(http.Dir(rootRepo)))
	t.Cleanup(ts.Close)
	return ts.URL
}

// preparePomFile prepares a POM file for testing by copying it and updating repository URLs
func preparePomFile(t *testing.T, rootPomFile, rootPomRepoRef string, repoURLs map[string]string) string {
	t.Helper()

	// If no root POM repo reference, use the original file
	if rootPomRepoRef == "" {
		return rootPomFile
	}

	// Copy root POM to temp directory and update repository URLs
	tempPomDir := t.TempDir()
	pomFileName := filepath.Base(rootPomFile)
	tempPomPath := filepath.Join(tempPomDir, pomFileName)

	// Copy the root POM
	content, err := os.ReadFile(rootPomFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tempPomPath, content, 0644))

	// Update repository URL in the root POM
	repoURL := repoURLs[rootPomRepoRef]
	addRepoURLToPOM(t, tempPomPath, repoURL)

	// Copy module POMs if they exist
	copyModulePoms(t, rootPomFile, tempPomDir)

	return tempPomPath
}

// copyModulePoms copies module directories from source to target
func copyModulePoms(t *testing.T, rootPomFile, targetDir string) {
	t.Helper()
	pomDir := filepath.Dir(rootPomFile)
	entries, err := os.ReadDir(pomDir)
	if err != nil {
		return // No modules or can't read directory
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		moduleDir := filepath.Join(pomDir, entry.Name())
		modulePomPath := filepath.Join(moduleDir, "pom.xml")
		if _, err := os.Stat(modulePomPath); err == nil {
			// Copy module directory
			targetModuleDir := filepath.Join(targetDir, entry.Name())
			testutil.CopyDir(t, moduleDir, targetModuleDir)
		}
	}
}

// verifyPackages verifies that expected packages are present with correct licenses
func verifyPackages(t *testing.T, pkgs []ftypes.Package, wantPackages map[string]string, matchWithoutHash bool) {
	t.Helper()

	// Create package map for easy lookup
	pkgMap := lo.SliceToMap(pkgs, func(p ftypes.Package) (string, ftypes.Package) {
		return p.ID, p
	})

	for wantID, wantLicense := range wantPackages {
		pkg, found := findPackage(pkgMap, wantID, matchWithoutHash)
		assert.True(t, found, "expected package %s not found", wantID)
		if !found {
			continue
		}
		assert.NotEmpty(t, pkg.Licenses, "expected license for package %s, but got none", wantID)
		if len(pkg.Licenses) > 0 {
			assert.Equal(t, wantLicense, pkg.Licenses[0], "license mismatch for package %s", wantID)
		}
	}
}

// findPackage finds a package in the map, optionally matching without hash
func findPackage(pkgMap map[string]ftypes.Package, wantID string, matchWithoutHash bool) (ftypes.Package, bool) {
	if !matchWithoutHash {
		// Exact match with hash
		pkg, found := pkgMap[wantID]
		return pkg, found
	}

	// Match by GAV without hash (for multi-module projects where hash varies)
	for id, pkg := range pkgMap {
		gav := extractGAV(id)
		if gav == wantID {
			return pkg, true
		}
	}
	return ftypes.Package{}, false
}

// extractGAV extracts groupId:artifactId:version from package ID
// Package ID format: "groupId:artifactId:version::hash"
func extractGAV(packageID string) string {
	// Find the last "::" to remove hash
	for i := len(packageID) - 1; i > 0; i-- {
		if packageID[i] == ':' && packageID[i-1] == ':' {
			return packageID[:i-1]
		}
	}
	return packageID
}

// splitGroupID splits a Maven groupID into path components
// e.g., "org.example" -> ["org", "example"]
func splitGroupID(groupID string) []string {
	return strings.Split(groupID, ".")
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
