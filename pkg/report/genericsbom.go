package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

type GsbomPackage struct {
	Purl         string   `json:"purl,omitempty"`
	Relationship string   `json:"relationship,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type GsbomFile struct {
	SrcLocation string `json:"source_location,omitempty"`
}

type GsbomManifest struct {
	Name string     `json:"name,omitempty"`
	File *GsbomFile `json:"file,omitempty"`
	//TODO can also be number or boolean
	Metadata map[string]string       `json:"metadata,omitempty"`
	Resolved map[string]GsbomPackage `json:"resolved,omitempty"`
}

type GsbomJob struct {
	Name string `json:"name,omitempty"`
	Id   int    `json:"id,omitempty"`
}

type Gsbom struct {
	Version   int                      `json:"version,omitempty"`
	Detector  string                   `json:"detector,omitempty"`
	Ref       string                   `json:"ref,omitempty"`
	Sha       string                   `json:"sha,omitempty"`
	Job       *GsbomJob                `json:"job,omitempty"`
	Scanned   string                   `json:"scanned,omitempty"`
	Manifests map[string]GsbomManifest `json:"manifests,omitempty"`
}

type GsbomWriter struct {
	Output io.Writer
}

func init() {
	CustomTemplateFuncMap["now"] = time.Now
}

func (gsbmw GsbomWriter) Write(report types.Report) error {
	gsbom := &Gsbom{}

	//use now() method that can be overwritten while integration tests run
	gsbom.Scanned = CustomTemplateFuncMap["now"].(func() time.Time)().Format(time.RFC3339)
	gsbom.Detector = "trivy"

	//TODO optionally add git information
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
