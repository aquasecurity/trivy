package cyclonedx

import (
	"encoding/json"
	"io"
	"path/filepath"

	"golang.org/x/xerrors"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

type Parser struct {
	extension string
}

func NewParser(name string) *Parser {
	return &Parser{
		extension: filepath.Ext(name),
	}
}

func (p Parser) Parse(r io.Reader) (string, *ftypes.OS, []ftypes.PackageInfo, []ftypes.Application, error) {
	b := TrivyBOM{}
	switch p.extension {
	case ".json":
		if err := json.NewDecoder(r).Decode(&b); err != nil {
			return "", nil, nil, nil, xerrors.Errorf("failed to json decode: %w", err)
		}
	case ".xml":
		// TODO: not supported yet
	default:
		return "", nil, nil, nil, xerrors.Errorf("invalid cycloneDX format: %s", p.extension)
	}

	if b.Components == nil {
		return b.SerialNumber, nil, nil, nil, nil
	}
	osBOMRef, os, appMap, libMap, err := b.parseComponents()
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to parse components: %w", err)
	}

	if b.Dependencies == nil {
		return b.SerialNumber, os, nil, nil, nil
	}

	var apps []ftypes.Application
	var pkgInfos []ftypes.PackageInfo
	var unrelatedLibs []cdx.Component
	for _, dep := range *b.Dependencies {
		if dep.Dependencies == nil {
			continue
		}

		var pkgInfo ftypes.PackageInfo
		app, appOk := appMap[dep.Ref]
		for _, d := range *dep.Dependencies {
			if a, ok := appMap[d.Ref]; ok {
				apps = append(apps, *a)
			}

			lib, ok := libMap[d.Ref]
			if !ok {
				continue
			}
			pkg, err := b.Package(lib)
			if err != nil {
				return "", nil, nil, nil, xerrors.Errorf("failed to parse package: %w", err)
			}

			if dep.Ref == osBOMRef {
				// OperationsSystem Ref depends on os libraries.
				pkgInfo.Packages = append(pkgInfo.Packages, *pkg)
			} else if !appOk {
				unrelatedLibs = append(unrelatedLibs, lib)
			} else {
				// Other Ref dependencies application libraries.
				if app.Type == "" {
					t, err := typeFromComponent(lib)
					if err != nil {
						return "", nil, nil, nil, xerrors.Errorf("failed to get type from component: %w", err)
					}
					app.Type = t
				}
				app.Libraries = append(app.Libraries, *pkg)
			}
		}
		if appOk {
			apps = append(apps, *app)
			delete(appMap, dep.Ref)
		}
		if len(pkgInfo.Packages) != 0 {
			pkgInfos = append(pkgInfos, pkgInfo)
		}
	}
	if len(unrelatedLibs) != 0 {
		aggregatedApps, err := b.Aggregate(unrelatedLibs)
		if err != nil {
			return "", nil, nil, nil, xerrors.Errorf("failed to aggregate libraries: %w", err)
		}
		apps = append(apps, aggregatedApps...)
	}

	return b.SerialNumber, os, pkgInfos, apps, nil
}

func (p Parser) Type() sbom.SBOMFormat {
	return FormatCycloneDX
}
