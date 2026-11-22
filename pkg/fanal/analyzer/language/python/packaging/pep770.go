package packaging

import (
	"bytes"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

// sbomApps returns the Rust crates listed in the SBOMs that a wheel ships in `.dist-info/sboms/`,
// as one cargo application per SBOM file.
// cf. https://peps.python.org/pep-0770/
func (a packagingAnalyzer) sbomApps(fsys fs.FS, distInfoDir string) []types.Application {
	sbomDir := path.Join(distInfoDir, "sboms")
	entries, err := fs.ReadDir(fsys, sbomDir)
	if err != nil {
		return nil
	}

	var apps []types.Application
	for _, entry := range entries {
		// PEP 770 allows any SBOM format and file name. Crates are only known to be listed in
		// the CycloneDX JSON that maturin generates, and SBOMs in other JSON formats decode to no crates.
		if entry.IsDir() || path.Ext(entry.Name()) != ".json" {
			continue
		}
		sbomPath := path.Join(sbomDir, entry.Name())
		var bom *cdx.BOM
		data, err := fs.ReadFile(fsys, sbomPath)
		if err == nil {
			bom, err = cyclonedx.DecodeJSON(bytes.NewReader(data))
		}
		if err != nil {
			a.logger.Warn("Unable to read PEP 770 SBOM", log.FilePath(sbomPath), log.Err(err))
			continue
		}

		if crates := cargoPackages(bom, sbomPath); len(crates) > 0 {
			apps = append(apps, types.Application{
				Type:     types.Cargo,
				FilePath: sbomPath,
				Packages: crates,
			})
		}
	}
	return apps
}

func cargoPackages(bom *cdx.BOM, sbomPath string) types.Packages {
	// BOM ref => package ID
	ids := make(map[string]string)
	var pkgs types.Packages
	for _, c := range lo.FromPtr(bom.Components) {
		// cargo-cyclonedx marks build dependencies as excluded; they are not part of the shipped binary.
		if c.Scope == cdx.ScopeExcluded {
			continue
		}
		p, err := purl.FromString(c.PackageURL)
		if err != nil || p.Type != packageurl.TypeCargo || p.Version == "" {
			continue
		}
		// The crates of the wheel's own workspace are not published to crates.io,
		// so matching them by name against advisories would only produce false positives.
		if strings.HasPrefix(p.Qualifiers.Map()["download_url"], "file://") {
			continue
		}
		pkg := p.Package()
		pkg.Licenses = licenses(c)
		pkg.FilePath = sbomPath
		ids[c.BOMRef] = pkg.ID
		pkgs = append(pkgs, *pkg)
	}

	dependsOn := make(map[string][]string)
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		id, ok := ids[dep.Ref]
		if !ok {
			continue
		}
		for _, ref := range lo.FromPtr(dep.Dependencies) {
			if depID, ok := ids[ref]; ok {
				dependsOn[id] = append(dependsOn[id], depID)
			}
		}
	}
	for i := range pkgs {
		deps := dependsOn[pkgs[i].ID]
		slices.Sort(deps)
		pkgs[i].DependsOn = slices.Compact(deps)
	}
	sort.Sort(pkgs)
	// Cargo can resolve the same name and version from more than one source.
	return slices.CompactFunc(pkgs, func(a, b types.Package) bool { return a.ID == b.ID })
}

func licenses(c cdx.Component) []string {
	var names []string
	for _, l := range lo.FromPtr(c.Licenses) {
		switch {
		case l.License != nil && l.License.Name != "":
			names = append(names, l.License.Name)
		case l.License != nil && l.License.ID != "":
			names = append(names, l.License.ID)
		case l.Expression != "":
			names = append(names, l.Expression)
		}
	}
	return names
}
