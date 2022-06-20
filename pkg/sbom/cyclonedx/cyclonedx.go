package cyclonedx

import (
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	Namespace = "aquasecurity:trivy:"

	PropertySchemaVersion = "SchemaVersion"
	PropertyType          = "Type"
	PropertyClass         = "Class"

	// Image properties
	PropertySize       = "Size"
	PropertyImageID    = "ImageID"
	PropertyRepoDigest = "RepoDigest"
	PropertyDiffID     = "DiffID"
	PropertyRepoTag    = "RepoTag"

	// Package properties
	PropertySrcName         = "SrcName"
	PropertySrcVersion      = "SrcVersion"
	PropertySrcRelease      = "SrcRelease"
	PropertySrcEpoch        = "SrcEpoch"
	PropertyModularitylabel = "Modularitylabel"
	PropertyFilePath        = "FilePath"
	PropertyLayerDigest     = "LayerDigest"
	PropertyLayerDiffID     = "LayerDiffID"
)

const (
	// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
	timeLayout = "2006-01-02T15:04:05+00:00"

	FormatCycloneDX sbom.SBOMFormat = "cyclonedx"
)

type CycloneDX struct {
	cdx.BOM
}

func (c CycloneDX) componentMap() map[string]cdx.Component {
	componentMap := make(map[string]cdx.Component)

	if c.Components == nil {
		return componentMap
	}

	for _, component := range *c.Components {
		componentMap[component.BOMRef] = component
	}
	if c.Metadata != nil {
		componentMap[c.Metadata.Component.BOMRef] = *c.Metadata.Component
	}
	return componentMap
}

func (c CycloneDX) dependenciesMap() map[string][]string {
	dependencyMap := make(map[string][]string)

	if c.Dependencies == nil {
		return dependencyMap
	}
	for _, dep := range *c.Dependencies {
		if _, ok := dependencyMap[dep.Ref]; ok {
			continue
		}

		var refs []string
		if dep.Dependencies != nil {
			for _, d := range *dep.Dependencies {
				refs = append(refs, d.Ref)
			}
		}

		dependencyMap[dep.Ref] = refs
	}
	return dependencyMap
}

func (c CycloneDX) parse() (string, *ftypes.OS, []ftypes.PackageInfo, []ftypes.Application, error) {
	depsMap := c.dependenciesMap()
	componentMap := c.componentMap()

	var OS *ftypes.OS
	var apps []ftypes.Application
	var pkgInfos []ftypes.PackageInfo
	usedComponent := make(map[string]struct{})
	for bomRef, deps := range depsMap {
		component := componentMap[bomRef]
		switch component.Type {
		case cdx.ComponentTypeOS:
			OS = c.OS(component)
			var components []cdx.Component
			components = parseDependencies(components, deps, componentMap, depsMap)

			var pkgInfo ftypes.PackageInfo
			for _, com := range components {
				usedComponent[com.BOMRef] = struct{}{}
				pkg, err := c.Package(com)
				if err != nil {
					return "", nil, nil, nil, xerrors.Errorf("failed to parse os package: %w", err)
				}
				pkgInfo.Packages = append(pkgInfo.Packages, *pkg)
			}
			pkgInfos = append(pkgInfos, pkgInfo)
		case cdx.ComponentTypeApplication:
			if getProperty(component.Properties, PropertyType) == "" {
				continue
			}
			app := c.Application(component)
			var components []cdx.Component
			components = parseDependencies(components, deps, componentMap, depsMap)

			for _, com := range components {
				usedComponent[com.BOMRef] = struct{}{}
				pkg, err := c.Package(com)
				if err != nil {
					return "", nil, nil, nil, xerrors.Errorf("failed to parse language package: %w", err)
				}
				app.Libraries = append(app.Libraries, *pkg)
			}
			apps = append(apps, *app)
		}
	}

	for bomRef := range usedComponent {
		delete(componentMap, bomRef)
	}

	var libComponents []cdx.Component
	for _, c := range componentMap {
		if c.Type != cdx.ComponentTypeLibrary {
			continue
		}
		libComponents = append(libComponents, c)
	}

	aggregatedApps, err := c.Aggregate(libComponents)
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to parse aggregate package: %w", err)
	}
	apps = append(apps, aggregatedApps...)

	return c.SerialNumber, OS, pkgInfos, apps, nil
}

func parseDependencies(components []cdx.Component, dependencies []string, componentMap map[string]cdx.Component, dependenciesMap map[string][]string) []cdx.Component {
	for _, dep := range dependencies {
		component, ok := componentMap[dep]
		if !ok {
			continue
		}
		components = append(components, component)

		deps, ok := dependenciesMap[dep]
		if !ok {
			continue
		}
		components = append(components, parseDependencies(components, deps, componentMap, dependenciesMap)...)
	}
	return components
}

func (c CycloneDX) Aggregate(libs []cdx.Component) ([]ftypes.Application, error) {
	appsMap := map[string]*ftypes.Application{}
	for _, lib := range libs {
		p, err := packageurl.FromString(lib.PackageURL)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse purl from string: %w", err)
		}

		app, ok := appsMap[p.Type]
		if !ok {
			app = &ftypes.Application{
				Type:     purl.Type(p.Type),
				FilePath: p.Type,
			}
			appsMap[p.Type] = app
		}
		pkg, err := c.Package(lib)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse purl to package: %w", err)
		}

		app.Libraries = append(app.Libraries, *pkg)
	}

	var apps []ftypes.Application
	for _, app := range appsMap {
		apps = append(apps, *app)
	}
	return apps, nil
}

func (c CycloneDX) OS(component cdx.Component) *ftypes.OS {
	return &ftypes.OS{
		Family: component.Name,
		Name:   component.Version,
	}
}

func (c CycloneDX) Application(component cdx.Component) *ftypes.Application {
	return &ftypes.Application{
		Type:     getProperty(component.Properties, PropertyType),
		FilePath: component.Name,
	}
}

func (c CycloneDX) Package(component cdx.Component) (*ftypes.Package, error) {
	pkg, err := purl.FromString(component.PackageURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl from string: %w", err)
	}
	pkg.Ref = component.BOMRef

	if component.Licenses != nil {
		for _, license := range *component.Licenses {
			pkg.License = license.Expression
		}
	}

	if component.Properties == nil {
		return pkg, nil
	}

	for _, p := range *component.Properties {
		if strings.HasPrefix(p.Name, Namespace) {
			switch strings.TrimPrefix(p.Name, Namespace) {
			case PropertySrcName:
				pkg.SrcName = p.Value
			case PropertySrcVersion:
				pkg.SrcVersion = p.Value
			case PropertySrcRelease:
				pkg.SrcRelease = p.Value
			case PropertySrcEpoch:
				pkg.SrcEpoch, err = strconv.Atoi(p.Value)
				if err != nil {
					return nil, xerrors.Errorf("failed to parse source epoch: %w", err)
				}
			case PropertyModularitylabel:
				pkg.Modularitylabel = p.Value
			case PropertyLayerDiffID:
				pkg.Layer.DiffID = p.Value
			}
		}
	}

	return pkg, nil
}

func Vulnerability(vuln types.DetectedVulnerability, bomRef string) cdx.Vulnerability {
	v := cdx.Vulnerability{
		ID:          vuln.VulnerabilityID,
		Source:      source(vuln.DataSource),
		Ratings:     ratings(vuln),
		CWEs:        cwes(vuln.CweIDs),
		Description: vuln.Description,
		Advisories:  advisories(vuln.References),
	}
	if vuln.PublishedDate != nil {
		v.Published = vuln.PublishedDate.Format(timeLayout)
	}
	if vuln.LastModifiedDate != nil {
		v.Updated = vuln.LastModifiedDate.Format(timeLayout)
	}

	v.Affects = &[]cdx.Affects{Affects(bomRef, vuln.InstalledVersion)}

	return v
}

func Affects(ref, version string) cdx.Affects {
	return cdx.Affects{
		Ref: ref,
		Range: &[]cdx.AffectedVersions{
			{
				Version: version,
				Status:  cdx.VulnerabilityStatusAffected,
				// "AffectedVersions.Range" is not included, because it does not exist in DetectedVulnerability.
			},
		},
	}
}

func Properties(pkg ftypes.Package) []cdx.Property {
	props := []struct {
		name  string
		value string
	}{
		{PropertyFilePath, pkg.FilePath},
		{PropertySrcName, pkg.SrcName},
		{PropertySrcVersion, pkg.SrcVersion},
		{PropertySrcRelease, pkg.SrcRelease},
		{PropertySrcEpoch, strconv.Itoa(pkg.SrcEpoch)},
		{PropertyModularitylabel, pkg.Modularitylabel},
		{PropertyLayerDigest, pkg.Layer.Digest},
		{PropertyLayerDiffID, pkg.Layer.DiffID},
	}

	var properties []cdx.Property
	for _, prop := range props {
		properties = AppendProperties(properties, prop.name, prop.value)
	}

	return properties
}

func AppendProperties(properties []cdx.Property, key, value string) []cdx.Property {
	if value == "" || (key == PropertySrcEpoch && value == "0") {
		return properties
	}
	return append(properties, Property(key, value))
}

func Property(key, value string) cdx.Property {
	return cdx.Property{
		Name:  Namespace + key,
		Value: value,
	}
}

func advisories(refs []string) *[]cdx.Advisory {
	var advs []cdx.Advisory
	for _, ref := range refs {
		advs = append(advs, cdx.Advisory{
			URL: ref,
		})
	}
	return &advs
}

func cwes(cweIDs []string) *[]int {
	// to skip cdx.Vulnerability.CWEs when generating json
	// we should return 'clear' nil without 'type' interface part
	if cweIDs == nil {
		return nil
	}
	var ret []int
	for _, cweID := range cweIDs {
		number, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(cweID), "cwe-"))
		if err != nil {
			log.Logger.Debugf("cwe id parse error: %s", err)
			continue
		}
		ret = append(ret, number)
	}
	return &ret
}

func ratings(vulnerability types.DetectedVulnerability) *[]cdx.VulnerabilityRating {
	var rates []cdx.VulnerabilityRating
	for sourceID, severity := range vulnerability.VendorSeverity {
		// When the vendor also provides CVSS score/vector
		if cvss, ok := vulnerability.CVSS[sourceID]; ok {
			if cvss.V2Score != 0 || cvss.V2Vector != "" {
				rates = append(rates, ratingV2(sourceID, severity, cvss))
			}
			if cvss.V3Score != 0 || cvss.V3Vector != "" {
				rates = append(rates, ratingV3(sourceID, severity, cvss))
			}
		} else { // When the vendor provides only severity
			rate := cdx.VulnerabilityRating{
				Source: &cdx.Source{
					Name: string(sourceID),
				},
				Severity: toCDXSeverity(severity),
			}
			rates = append(rates, rate)
		}
	}

	// For consistency
	sort.Slice(rates, func(i, j int) bool {
		if rates[i].Source.Name != rates[j].Source.Name {
			return rates[i].Source.Name < rates[j].Source.Name
		}
		if rates[i].Method != rates[j].Method {
			return rates[i].Method < rates[j].Method
		}
		if rates[i].Score != nil && rates[j].Score != nil {
			return *rates[i].Score < *rates[j].Score
		}
		return rates[i].Vector < rates[j].Vector
	})
	return &rates
}

func ratingV2(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	cdxSeverity := toCDXSeverity(severity)

	// Trivy keeps only CVSSv3 severity for NVD.
	// The CVSSv2 severity must be calculated according to CVSSv2 score.
	if sourceID == vulnerability.NVD {
		cdxSeverity = nvdSeverityV2(cvss.V2Score)
	}
	return cdx.VulnerabilityRating{
		Source: &cdx.Source{
			Name: string(sourceID),
		},
		Score:    &cvss.V2Score,
		Method:   cdx.ScoringMethodCVSSv2,
		Severity: cdxSeverity,
		Vector:   cvss.V2Vector,
	}
}

func nvdSeverityV2(score float64) cdx.Severity {
	// cf. https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	case score < 4.0:
		return cdx.SeverityInfo
	case 4.0 <= score && score < 7.0:
		return cdx.SeverityMedium
	case 7.0 <= score:
		return cdx.SeverityHigh
	}
	return cdx.SeverityUnknown
}

func ratingV3(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	rate := cdx.VulnerabilityRating{
		Source: &cdx.Source{
			Name: string(sourceID),
		},
		Score:    &cvss.V3Score,
		Method:   cdx.ScoringMethodCVSSv3,
		Severity: toCDXSeverity(severity),
		Vector:   cvss.V3Vector,
	}
	if strings.HasPrefix(cvss.V3Vector, "CVSS:3.1") {
		rate.Method = cdx.ScoringMethodCVSSv31
	}
	return rate
}

func toCDXSeverity(s dtypes.Severity) cdx.Severity {
	switch s {
	case dtypes.SeverityLow:
		return cdx.SeverityLow
	case dtypes.SeverityMedium:
		return cdx.SeverityMedium
	case dtypes.SeverityHigh:
		return cdx.SeverityHigh
	case dtypes.SeverityCritical:
		return cdx.SeverityCritical
	default:
		return cdx.SeverityUnknown
	}
}

func source(source *dtypes.DataSource) *cdx.Source {
	if source == nil {
		return nil
	}

	return &cdx.Source{
		Name: string(source.ID),
		URL:  source.URL,
	}
}

func getProperty(properties *[]cdx.Property, key string) string {
	if properties == nil {
		return ""
	}

	for _, p := range *properties {
		if p.Name == Namespace+key {
			return p.Value
		}
	}
	return ""
}
