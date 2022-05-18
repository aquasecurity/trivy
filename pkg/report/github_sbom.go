package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	DirectRelationship   string = "direct"
	IndirectRelationship string = "indirect"
	RuntimeScope         string = "runtime"
	DevelopmentScope     string = "development"
)

type GithubSbomPackage struct {
	PackageUrl   string   `json:"package_url,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Metadata     Metadata `json:"metadata,omitempty"`
}

type GithubSbomFile struct {
	SrcLocation string `json:"source_location,omitempty"`
}

type Metadata map[string]interface{}

type GithubSbomManifest struct {
	Name     string                       `json:"name,omitempty"`
	File     *GithubSbomFile              `json:"file,omitempty"`
	Metadata Metadata                     `json:"metadata,omitempty"`
	Resolved map[string]GithubSbomPackage `json:"resolved,omitempty"`
}

type GithubSbomJob struct {
	Correlator string `json:"correlator,omitempty"`
	Id         string `json:"id,omitempty"`
}
type GithubSbomDetector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Url     string `json:"url"`
}

type GithubSbom struct {
	Version   int                           `json:"version,omitempty"`
	Detector  GithubSbomDetector            `json:"detector"`
	Metadata  Metadata                      `json:"metadata,omitempty"`
	Ref       string                        `json:"ref,omitempty"`
	Sha       string                        `json:"sha,omitempty"`
	Job       *GithubSbomJob                `json:"job,omitempty"`
	Scanned   string                        `json:"scanned,omitempty"`
	Manifests map[string]GithubSbomManifest `json:"manifests,omitempty"`
}

type GithubSbomWriter struct {
	Output  io.Writer
	Version string
}

func init() {
	CustomTemplateFuncMap["now"] = time.Now
	CustomTemplateFuncMap["getenv"] = os.Getenv
}

func (gsbmw GithubSbomWriter) Write(report types.Report) error {
	getenv, ok := CustomTemplateFuncMap["getenv"].(func(string) string)
	if !ok {
		return xerrors.Errorf("invalid getenv reference")
	}
	githubSbom := &GithubSbom{}

	//use now() method that can be overwritten while integration tests run
	githubSbom.Scanned = CustomTemplateFuncMap["now"].(func() time.Time)().Format(time.RFC3339)
	githubSbom.Detector = GithubSbomDetector{
		Name:    "trivy",
		Version: gsbmw.Version,
		Url:     "https://github.com/aquasecurity/trivy",
	}
	githubSbom.Version = 0 // The version of the repository snapshot submission. It's not clear what value to set

	githubSbom.Ref = getenv("GITHUB_REF")
	githubSbom.Sha = getenv("GITHUB_SHA")

	githubSbom.Job = &GithubSbomJob{
		Correlator: (fmt.Sprintf("%s_%s", getenv("GITHUB_WORKFLOW"), getenv("GITHUB_JOB"))),
		Id:         getenv("GITHUB_RUN_ID"),
	}

	githubSbom.Metadata = getMetadata(report)

	manifests := make(map[string]GithubSbomManifest)

	for _, result := range report.Results {
		manifest := GithubSbomManifest{}
		manifest.Name = result.Type
		//show path for languages only
		if result.Class == types.ClassLangPkg {
			manifest.File = &GithubSbomFile{
				SrcLocation: result.Target,
			}
		}
		if result.Packages == nil {
			return xerrors.Errorf("unable to find packages")
		}

		resolved := make(map[string]GithubSbomPackage)

		for _, pkg := range result.Packages {
			var err error
			githubSbomPkg := GithubSbomPackage{}
			githubSbomPkg.Scope = RuntimeScope
			githubSbomPkg.Relationship = getPkgRelationshipType(pkg)
			githubSbomPkg.Dependencies = getDependencies(report.Results, pkg)
			githubSbomPkg.PackageUrl, err = buildPurl(result.Type, pkg)
			if err != nil {
				return xerrors.Errorf("unable to build purl: %w for the package: %s", err, pkg.Name)
			}

			resolved[pkg.Name] = githubSbomPkg
		}

		manifest.Resolved = resolved
		manifests[result.Target] = manifest
	}

	githubSbom.Manifests = manifests

	output, err := json.MarshalIndent(githubSbom, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal github sbom: %w", err)
	}

	if _, err = fmt.Fprint(gsbmw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write github sbom: %w", err)
	}
	return nil
}

func getMetadata(report types.Report) Metadata {
	metadata := Metadata{}
	if report.Metadata.RepoTags != nil {
		metadata["aquasecurity:trivy:RepoTag"] = strings.Join(report.Metadata.RepoTags, ",")
	}
	if report.Metadata.RepoDigests != nil {
		metadata["aquasecurity:trivy:RepoDigest"] = strings.Join(report.Metadata.RepoDigests, ",")
	}
	return metadata
}

func getDependencies(results []types.Result, pkg ftypes.Package) []string {
	for _, result := range results {
		for _, dep := range result.Dependencies {
			if dep.ID == pkg.ID {
				return dep.DependsOn
			}
		}
	}
	return []string{}
}

func getPkgRelationshipType(pkg ftypes.Package) string {
	if pkg.Indirect {
		return IndirectRelationship
	}
	return DirectRelationship
}

func buildPurl(t string, pkg ftypes.Package) (string, error) {
	packageUrl, err := purl.NewPackageURL(t, types.Metadata{}, pkg)
	if err != nil {
		return "", err
	}
	return packageUrl.ToString(), nil
}
