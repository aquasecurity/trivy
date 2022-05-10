package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

type GsbomPackage struct {
	Purl         string   `json:"purl,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Metadata     Metadata `json:"metadata,omitempty"`
}

type GsbomFile struct {
	SrcLocation string `json:"source_location,omitempty"`
}

//TODO can also be number or boolean
type Metadata map[string]interface{}

type GsbomManifest struct {
	Name     string                  `json:"name,omitempty"`
	File     *GsbomFile              `json:"file,omitempty"`
	Metadata Metadata                `json:"metadata,omitempty"`
	Resolved map[string]GsbomPackage `json:"resolved,omitempty"`
}

type GsbomJob struct {
	Name string `json:"name,omitempty"`
	Id   string `json:"id,omitempty"`
}
type GsbomDetector struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Url     string `json:"url,omitempty"`
}

type Gsbom struct {
	Version   int                      `json:"version,omitempty"`
	Detector  GsbomDetector            `json:"detector,omitempty"`
	Ref       string                   `json:"ref,omitempty"`
	Sha       string                   `json:"sha,omitempty"`
	Job       *GsbomJob                `json:"job,omitempty"`
	Scanned   string                   `json:"scanned,omitempty"`
	Manifests map[string]GsbomManifest `json:"manifests,omitempty"`
}

type GsbomWriter struct {
	Output  io.Writer
	Version string
}

func init() {
	CustomTemplateFuncMap["now"] = time.Now
	CustomTemplateFuncMap["getenv"] = os.Getenv
}

func (gsbmw GsbomWriter) Write(report types.Report) error {
	getenv, ok := CustomTemplateFuncMap["getenv"].(func(string) string)
	if !ok {
		return xerrors.Errorf("invalid getenv reference")
	}
	gsbom := &Gsbom{}

	//use now() method that can be overwritten while integration tests run
	gsbom.Scanned = CustomTemplateFuncMap["now"].(func() time.Time)().Format(time.RFC3339)
	gsbom.Detector = GsbomDetector{
		Name:    "trivy",
		Version: gsbmw.Version,
		Url:     "https://github.com/aquasecurity/trivy",
	}
	gsbom.Version = 1 // The version of the repository snapshot submission. It's not clear what value to set

	gsbom.Ref = getenv("GITHUB_REF")
	gsbom.Sha = getenv("GITHUB_SHA")

	gsbom.Job = &GsbomJob{
		Name: getenv("GITHUB_JOB"),
		Id:   getenv("GITHUB_RUN_ID"),
	}

	manifests := make(map[string]GsbomManifest)

	for _, result := range report.Results {
		manifest := GsbomManifest{}
		manifest.Name = result.Type
		//show path for languages only
		if result.Class == types.ClassLangPkg {
			manifest.File = &GsbomFile{
				SrcLocation: result.Target,
			}
		}
		if result.Packages == nil {
			return xerrors.Errorf("unable to find packages")
		}

		resolved := make(map[string]GsbomPackage)

		for _, pkg := range result.Packages {
			var err error
			gsbompkg := GsbomPackage{}
			gsbompkg.Scope = RuntimeScope
			gsbompkg.Relationship = DirectRelationship
			gsbompkg.Purl, err = buildPurl(result.Type, pkg)
			if err != nil {
				return xerrors.Errorf("unable to build purl: %w for the package: %s", err, pkg.Name)
			}
			resolved[pkg.Name] = gsbompkg
		}

		manifest.Resolved = resolved
		manifests[result.Target] = manifest
	}

	gsbom.Manifests = manifests

	output, err := json.MarshalIndent(gsbom, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal generic sbom: %w", err)
	}

	if _, err = fmt.Fprint(gsbmw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write generic sbom: %w", err)
	}
	return nil
}

func buildPurl(t string, pkg ftypes.Package) (string, error) {
	packageUrl, err := purl.NewPackageURL(t, types.Metadata{}, pkg)
	if err != nil {
		return "", err
	}
	return packageUrl.ToString(), nil

}
