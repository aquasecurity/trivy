package github

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	DirectRelationship   string = "direct"
	IndirectRelationship string = "indirect"
	RuntimeScope         string = "runtime"
	DevelopmentScope     string = "development"
)

type Package struct {
	PackageUrl   string   `json:"package_url,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Metadata     Metadata `json:"metadata,omitempty"`
}

type File struct {
	SrcLocation string `json:"source_location,omitempty"`
}

type Metadata map[string]interface{}

type Manifest struct {
	Name     string             `json:"name,omitempty"`
	File     *File              `json:"file,omitempty"`
	Metadata Metadata           `json:"metadata,omitempty"`
	Resolved map[string]Package `json:"resolved,omitempty"`
}

type Job struct {
	Correlator string `json:"correlator,omitempty"`
	Id         string `json:"id,omitempty"`
}
type Detector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Url     string `json:"url"`
}

type DependencySnapshot struct {
	Version   int                 `json:"version"`
	Detector  Detector            `json:"detector"`
	Metadata  Metadata            `json:"metadata,omitempty"`
	Ref       string              `json:"ref,omitempty"`
	Sha       string              `json:"sha,omitempty"`
	Job       *Job                `json:"job,omitempty"`
	Scanned   string              `json:"scanned,omitempty"`
	Manifests map[string]Manifest `json:"manifests,omitempty"`
}

// Writer generates JSON for GitHub Dependency Snapshots
type Writer struct {
	Output  io.Writer
	Version string
}

func (w Writer) Write(report types.Report) error {
	snapshot := &DependencySnapshot{}

	//use now() method that can be overwritten while integration tests run
	snapshot.Scanned = clock.Now().Format(time.RFC3339)
	snapshot.Detector = Detector{
		Name:    "trivy",
		Version: w.Version,
		Url:     "https://github.com/aquasecurity/trivy",
	}
	snapshot.Version = 0 // The version of the repository snapshot submission.

	snapshot.Ref = os.Getenv("GITHUB_REF")
	snapshot.Sha = os.Getenv("GITHUB_SHA")

	snapshot.Job = &Job{
		Correlator: fmt.Sprintf("%s_%s", os.Getenv("GITHUB_WORKFLOW"), os.Getenv("GITHUB_JOB")),
		Id:         os.Getenv("GITHUB_RUN_ID"),
	}

	snapshot.Metadata = getMetadata(report)

	manifests := make(map[string]Manifest)

	for _, result := range report.Results {
		if result.Packages == nil {
			continue
		}

		manifest := Manifest{}
		manifest.Name = string(result.Type)
		// show path for language-specific packages only
		if result.Class == types.ClassLangPkg {
			manifest.File = &File{
				SrcLocation: result.Target,
			}
		}

		resolved := make(map[string]Package)

		for _, pkg := range result.Packages {
			var err error
			githubPkg := Package{}
			githubPkg.Scope = RuntimeScope
			githubPkg.Relationship = getPkgRelationshipType(pkg)
			githubPkg.Dependencies = pkg.DependsOn // TODO: replace with PURL
			githubPkg.PackageUrl, err = buildPurl(result.Type, pkg)
			if err != nil {
				return xerrors.Errorf("unable to build purl for %s: %w", pkg.Name, err)
			}

			resolved[pkg.Name] = githubPkg
		}

		manifest.Resolved = resolved
		manifests[result.Target] = manifest
	}

	snapshot.Manifests = manifests

	output, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal github dependency snapshots: %w", err)
	}

	if _, err = fmt.Fprint(w.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write github dependency snapshots: %w", err)
	}
	return nil
}

func getMetadata(report types.Report) Metadata {
	metadata := Metadata{}
	if report.Metadata.RepoTags != nil {
		metadata["aquasecurity:trivy:RepoTag"] = strings.Join(report.Metadata.RepoTags, ", ")
	}
	if report.Metadata.RepoDigests != nil {
		metadata["aquasecurity:trivy:RepoDigest"] = strings.Join(report.Metadata.RepoDigests, ", ")
	}
	return metadata
}

func getPkgRelationshipType(pkg ftypes.Package) string {
	if pkg.Indirect {
		return IndirectRelationship
	}
	return DirectRelationship
}

func buildPurl(t ftypes.TargetType, pkg ftypes.Package) (string, error) {
	packageUrl, err := purl.NewPackageURL(t, types.Metadata{}, pkg)
	if err != nil {
		return "", xerrors.Errorf("purl error: %w", err)
	}
	return packageUrl.ToString(), nil
}
