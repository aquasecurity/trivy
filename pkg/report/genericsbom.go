package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
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
type depsRslvr func(result Result) map[string]GsbomPackage

func (gsbmw GsbomWriter) Write(report Report) error {
	gsbom := &Gsbom{}

	gsbom.Scanned = time.Now().Format(time.RFC3339)
	gsbom.Detector = "trivy"

	//TODO optionally add git information
	manifests := make(map[string]GsbomManifest)

	for _, result := range report.Results {
		manifest := GsbomManifest{}
		manifest.Name = result.Type
		//show path for languages only
		if result.Class == ClassLangPkg {
			manifest.File = &GsbomFile{
				SrcLocation: result.Target,
			}
		}
		var resolver depsRslvr
		if result.Packages != nil {
			resolver = resolvedFromPackages
		} else {
			resolver = resolvedFromVulns
		}
		manifest.Resolved = resolver(result)
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
func buildPurl(pkgName, version, pkgType string) string {
	//TODO fix maven namespace
	return packageurl.NewPackageURL(toPurlType(pkgType), "", pkgName, version, nil, "").ToString()
}

var resolvedFromVulns = func(result Result) map[string]GsbomPackage {
	resolved := make(map[string]GsbomPackage)
	for _, vuln := range result.Vulnerabilities {
		pkg := GsbomPackage{}
		pkg.Purl = buildPurl(vuln.PkgName, vuln.InstalledVersion, result.Type)
		resolved[vuln.PkgName] = pkg
	}
	return resolved
}
var resolvedFromPackages = func(result Result) map[string]GsbomPackage {
	resolved := make(map[string]GsbomPackage)
	for _, pkg := range result.Packages {
		gsbompkg := GsbomPackage{}
		gsbompkg.Purl = buildPurl(pkg.Name, pkg.Version, result.Type)
		resolved[pkg.Name] = gsbompkg
	}
	return resolved
}

func toPurlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "go":
		return "golang"
	case "gradle", "pom":
		return "maven"
	case "yarn":
		return "npm"
	case "packagist":
		return "composer"
	case "pip", "pipenv", "poetry":
		return "pypi"
	case "bundler", "rubygems":
		return "gem"
	default:
		return ecosystem
	}

}
