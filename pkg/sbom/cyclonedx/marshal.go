package cyclonedx

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	ToolVendor = "aquasecurity"
	ToolName   = "trivy"
	Namespace  = ToolVendor + ":" + ToolName + ":"

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
	PropertyPkgID           = "PkgID"
	PropertyPkgType         = "PkgType"
	PropertySrcName         = "SrcName"
	PropertySrcVersion      = "SrcVersion"
	PropertySrcRelease      = "SrcRelease"
	PropertySrcEpoch        = "SrcEpoch"
	PropertyModularitylabel = "Modularitylabel"
	PropertyFilePath        = "FilePath"
	PropertyLayerDigest     = "LayerDigest"
	PropertyLayerDiffID     = "LayerDiffID"

	// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
	timeLayout = "2006-01-02T15:04:05+00:00"
)

var (
	ErrInvalidBOMLink = xerrors.New("invalid bomLink format error")
)

type Marshaler struct {
	appVersion string // Trivy version
	clock      clock.Clock
	newUUID    newUUID
}

type newUUID func() uuid.UUID

type marshalOption func(*Marshaler)

func WithClock(clock clock.Clock) marshalOption {
	return func(opts *Marshaler) {
		opts.clock = clock
	}
}

func WithNewUUID(newUUID newUUID) marshalOption {
	return func(opts *Marshaler) {
		opts.newUUID = newUUID
	}
}

func NewMarshaler(version string, opts ...marshalOption) *Marshaler {
	e := &Marshaler{
		appVersion: version,
		clock:      clock.RealClock{},
		newUUID:    uuid.New,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Marshal converts the Trivy report to the CycloneDX format
func (e *Marshaler) Marshal(report types.Report) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = e.newUUID().URN()
	metadataComponent, err := e.reportToCdxComponent(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse metadata component: %w", err)
	}

	bom.Metadata = e.cdxMetadata()
	bom.Metadata.Component = metadataComponent

	bom.Components, bom.Dependencies, bom.Vulnerabilities, err = e.marshalComponents(report, bom.Metadata.Component.BOMRef)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse components: %w", err)
	}

	return bom, nil
}

// MarshalVulnerabilities converts the Trivy report to the CycloneDX format only with vulnerabilities.
// The output refers to another CycloneDX SBOM.
func (e *Marshaler) MarshalVulnerabilities(report types.Report) (*cdx.BOM, error) {
	vulnMap := map[string]cdx.Vulnerability{}
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			ref, err := externalRef(report.CycloneDX.SerialNumber, vuln.Ref)
			if err != nil {
				return nil, err
			}
			if v, ok := vulnMap[vuln.VulnerabilityID]; ok {
				*v.Affects = append(*v.Affects, cdxAffects(ref, vuln.InstalledVersion))
			} else {
				vulnMap[vuln.VulnerabilityID] = toCdxVulnerability(ref, vuln)
			}
		}
	}
	vulns := maps.Values(vulnMap)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID > vulns[j].ID
	})

	bom := cdx.NewBOM()
	bom.Metadata = e.cdxMetadata()

	// Fill the detected vulnerabilities
	bom.Vulnerabilities = &vulns

	// Use the original component as is
	bom.Metadata.Component = &cdx.Component{
		Name:    report.CycloneDX.Metadata.Component.Name,
		Version: report.CycloneDX.Metadata.Component.Version,
		Type:    cdx.ComponentType(report.CycloneDX.Metadata.Component.Type),
	}

	// Overwrite the bom ref as it must be the BOM ref of the original CycloneDX.
	// e.g.
	//  "metadata" : {
	//    "timestamp" : "2022-07-02T00:00:00Z",
	//    "component" : {
	//      "name" : "Acme Product",
	//      "version": "2.4.0",
	//      "type" : "application",
	//      "bom-ref" : "urn:cdx:f08a6ccd-4dce-4759-bd84-c626675d60a7/1"
	//    }
	//  },
	if report.CycloneDX.SerialNumber != "" { // bomRef is optional field - https://cyclonedx.org/docs/1.4/json/#metadata_component_bom-ref
		bom.Metadata.Component.BOMRef = fmt.Sprintf("%s/%d", report.CycloneDX.SerialNumber, report.CycloneDX.Version)
	}
	return bom, nil
}

func (e *Marshaler) cdxMetadata() *cdx.Metadata {
	return &cdx.Metadata{
		Timestamp: e.clock.Now().UTC().Format(timeLayout),
		Tools: &[]cdx.Tool{
			{
				Vendor:  ToolVendor,
				Name:    ToolName,
				Version: e.appVersion,
			},
		},
	}
}

func externalRef(bomLink string, bomRef string) (string, error) {
	// bomLink is optional field: https://cyclonedx.org/docs/1.4/json/#vulnerabilities_items_bom-ref
	if bomLink == "" {
		return bomRef, nil
	}
	if !strings.HasPrefix(bomLink, "urn:uuid:") {
		return "", xerrors.Errorf("%q: %w", bomLink, ErrInvalidBOMLink)
	}
	return fmt.Sprintf("%s/%d#%s", strings.Replace(bomLink, "uuid", "cdx", 1), cdx.BOMFileFormatJSON, bomRef), nil
}

func (e *Marshaler) marshalComponents(r types.Report, bomRef string) (*[]cdx.Component, *[]cdx.Dependency, *[]cdx.Vulnerability, error) {
	components := make([]cdx.Component, 0) // To export an empty array in JSON
	// we use map to avoid duplicate components
	dependencies := map[string]cdx.Dependency{}
	metadataDependencies := make([]string, 0) // To export an empty array in JSON
	libraryUniqMap := map[string]struct{}{}
	vulnMap := map[string]cdx.Vulnerability{}
	for _, result := range r.Results {
		bomRefMap := map[string]string{}
		pkgIDToRef := map[string]string{}
		var directDepRefs []string

		// Get dependency parents first
		parents := ftypes.Packages(result.Packages).ParentDeps()

		for _, pkg := range result.Packages {
			pkgComponent, err := pkgToCdxComponent(result.Type, r.Metadata, pkg)
			if err != nil {
				return nil, nil, nil, xerrors.Errorf("failed to parse pkg: %w", err)
			}
			pkgID := packageID(result.Target, pkg.Name, utils.FormatVersion(pkg), pkg.FilePath)
			bomRefMap[pkgID] = pkgComponent.BOMRef
			if pkg.ID != "" {
				pkgIDToRef[pkg.ID] = pkgComponent.BOMRef
			}
			// This package is a direct dependency
			if !pkg.Indirect || len(parents[pkg.ID]) == 0 {
				directDepRefs = append(directDepRefs, pkgComponent.BOMRef)
			}

			// When multiple lock files have the same dependency with the same name and version,
			// "bom-ref" (PURL technically) of Library components may conflict.
			// In that case, only one Library component will be added and
			// some Application components will refer to the same component.
			// e.g.
			//    Application component (/app1/package-lock.json)
			//    |
			//    |    Application component (/app2/package-lock.json)
			//    |    |
			//    └----┴----> Library component (npm package, express-4.17.3)
			//
			if _, ok := libraryUniqMap[pkgComponent.BOMRef]; !ok {
				libraryUniqMap[pkgComponent.BOMRef] = struct{}{}

				// For components
				// ref. https://cyclonedx.org/use-cases/#inventory
				components = append(components, pkgComponent)
			}
		}

		// Iterate packages again to build dependency graph
		for _, pkg := range result.Packages {
			deps := lo.FilterMap(pkg.DependsOn, func(dep string, _ int) (string, bool) {
				if ref, ok := pkgIDToRef[dep]; ok {
					return ref, true
				}
				return "", false
			})
			if len(deps) == 0 {
				continue
			}
			sort.Strings(deps)
			ref := pkgIDToRef[pkg.ID]
			dependencies[ref] = cdx.Dependency{
				Ref:          ref,
				Dependencies: &deps,
			}
		}
		sort.Strings(directDepRefs)

		for _, vuln := range result.Vulnerabilities {
			// Take a bom-ref
			pkgID := packageID(result.Target, vuln.PkgName, vuln.InstalledVersion, vuln.PkgPath)
			ref := bomRefMap[pkgID]
			if v, ok := vulnMap[vuln.VulnerabilityID]; ok {
				// If a vulnerability depends on multiple packages,
				// it will be commonised into a single vulnerability.
				//   Vulnerability component (CVE-2020-26247)
				//     -> Library component (nokogiri /srv/app1/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
				//     -> Library component (nokogiri /srv/app2/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
				*v.Affects = append(*v.Affects, cdxAffects(ref, vuln.InstalledVersion))
			} else {
				vulnMap[vuln.VulnerabilityID] = toCdxVulnerability(ref, vuln)
			}
		}

		if result.Type == ftypes.NodePkg || result.Type == ftypes.PythonPkg ||
			result.Type == ftypes.GemSpec || result.Type == ftypes.Jar || result.Type == ftypes.CondaPkg {
			// If a package is language-specific package that isn't associated with a lock file,
			// it will be a dependency of a component under "metadata".
			// e.g.
			//   Container component (alpine:3.15) ----------------------- #1
			//     -> Library component (npm package, express-4.17.3) ---- #2
			//     -> Library component (python package, django-4.0.2) --- #2
			//     -> etc.
			// ref. https://cyclonedx.org/use-cases/#inventory

			// Dependency graph from #1 to #2
			metadataDependencies = append(metadataDependencies, directDepRefs...)
		} else if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
			// If a package is OS package, it will be a dependency of "Operating System" component.
			// e.g.
			//   Container component (alpine:3.15) --------------------- #1
			//     -> Operating System Component (Alpine Linux 3.15) --- #2
			//       -> Library component (bash-4.12) ------------------ #3
			//       -> Library component (vim-8.2)   ------------------ #3
			//       -> etc.
			//
			// Else if a package is language-specific package associated with a lock file,
			// it will be a dependency of "Application" component.
			// e.g.
			//   Container component (alpine:3.15) ------------------------ #1
			//     -> Application component (/app/package-lock.json) ------ #2
			//       -> Library component (npm package, express-4.17.3) --- #3
			//       -> Library component (npm package, lodash-4.17.21) --- #3
			//       -> etc.

			resultComponent := e.resultToCdxComponent(result, r.Metadata.OS)
			components = append(components, resultComponent)

			// Dependency graph from #2 to #3
			dependencies[resultComponent.BOMRef] = cdx.Dependency{
				Ref:          resultComponent.BOMRef,
				Dependencies: &directDepRefs,
			}
			// Dependency graph from #1 to #2
			metadataDependencies = append(metadataDependencies, resultComponent.BOMRef)
		}
	}

	vulns := maps.Values(vulnMap)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID > vulns[j].ID
	})

	dependencies[bomRef] = cdx.Dependency{
		Ref:          bomRef,
		Dependencies: &metadataDependencies,
	}
	dependencyList := maps.Values(dependencies)
	sort.Slice(dependencyList, func(i, j int) bool {
		return dependencyList[i].Ref < dependencyList[j].Ref
	})
	return &components, &dependencyList, &vulns, nil
}

func packageID(target, pkgName, pkgVersion, pkgFilePath string) string {
	return fmt.Sprintf("%s/%s/%s/%s", target, pkgName, pkgVersion, pkgFilePath)
}

func toCdxVulnerability(bomRef string, vuln types.DetectedVulnerability) cdx.Vulnerability {
	v := cdx.Vulnerability{
		ID:          vuln.VulnerabilityID,
		Source:      cdxSource(vuln.DataSource),
		Ratings:     cdxRatings(vuln),
		CWEs:        cwes(vuln.CweIDs),
		Description: vuln.Description,
		Advisories:  cdxAdvisories(vuln.References),
	}
	if vuln.FixedVersion != "" {
		v.Recommendation = fmt.Sprintf("Upgrade %s to version %s", vuln.PkgName, vuln.FixedVersion)
	}
	if vuln.PublishedDate != nil {
		v.Published = vuln.PublishedDate.Format(timeLayout)
	}
	if vuln.LastModifiedDate != nil {
		v.Updated = vuln.LastModifiedDate.Format(timeLayout)
	}

	v.Affects = &[]cdx.Affects{cdxAffects(bomRef, vuln.InstalledVersion)}

	return v
}

func (e *Marshaler) reportToCdxComponent(r types.Report) (*cdx.Component, error) {
	component := &cdx.Component{
		Name: r.ArtifactName,
	}

	properties := []cdx.Property{
		cdxProperty(PropertySchemaVersion, strconv.Itoa(r.SchemaVersion)),
	}

	if r.Metadata.Size != 0 {
		properties = appendProperties(properties, PropertySize, strconv.FormatInt(r.Metadata.Size, 10))
	}

	switch r.ArtifactType {
	case ftypes.ArtifactContainerImage:
		component.Type = cdx.ComponentTypeContainer
		p, err := purl.NewPackageURL(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
		}
		properties = appendProperties(properties, PropertyImageID, r.Metadata.ImageID)

		if p.Type == "" {
			component.BOMRef = e.newUUID().String()
		} else {
			component.BOMRef = p.ToString()
			component.PackageURL = p.ToString()
		}
	case ftypes.ArtifactFilesystem, ftypes.ArtifactRemoteRepository:
		component.Type = cdx.ComponentTypeApplication
		component.BOMRef = e.newUUID().String()
	}

	for _, d := range r.Metadata.RepoDigests {
		properties = appendProperties(properties, PropertyRepoDigest, d)
	}
	for _, d := range r.Metadata.DiffIDs {
		properties = appendProperties(properties, PropertyDiffID, d)
	}
	for _, t := range r.Metadata.RepoTags {
		properties = appendProperties(properties, PropertyRepoTag, t)
	}

	component.Properties = &properties

	return component, nil
}

func (e *Marshaler) resultToCdxComponent(r types.Result, osFound *ftypes.OS) cdx.Component {
	component := cdx.Component{
		Name: r.Target,
		Properties: &[]cdx.Property{
			cdxProperty(PropertyType, r.Type),
			cdxProperty(PropertyClass, string(r.Class)),
		},
	}

	switch r.Class {
	case types.ClassOSPkg:
		// UUID needs to be generated since Operating System Component cannot generate PURL.
		// https://cyclonedx.org/use-cases/#known-vulnerabilities
		component.BOMRef = e.newUUID().String()
		if osFound != nil {
			component.Name = osFound.Family
			component.Version = osFound.Name
		}
		component.Type = cdx.ComponentTypeOS
	case types.ClassLangPkg:
		// UUID needs to be generated since Application Component cannot generate PURL.
		// https://cyclonedx.org/use-cases/#known-vulnerabilities
		component.BOMRef = e.newUUID().String()
		component.Type = cdx.ComponentTypeApplication
	case types.ClassConfig:
		// TODO: Config support
		component.BOMRef = e.newUUID().String()
		component.Type = cdx.ComponentTypeFile
	}

	return component
}

func pkgToCdxComponent(pkgType string, meta types.Metadata, pkg ftypes.Package) (cdx.Component, error) {
	pu, err := purl.NewPackageURL(pkgType, meta, pkg)
	if err != nil {
		return cdx.Component{}, xerrors.Errorf("failed to new package purl: %w", err)
	}
	properties := cdxProperties(pkgType, pkg)
	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.Name,
		Version:    pu.Version,
		BOMRef:     pu.BOMRef(),
		PackageURL: pu.ToString(),
		Properties: properties,
	}

	if len(pkg.Licenses) != 0 {
		choices := lo.Map(pkg.Licenses, func(license string, i int) cdx.LicenseChoice {
			return cdx.LicenseChoice{Expression: license}
		})
		component.Licenses = lo.ToPtr(cdx.Licenses(choices))
	}

	return component, nil
}

func cdxProperties(pkgType string, pkg ftypes.Package) *[]cdx.Property {
	props := []struct {
		name  string
		value string
	}{
		{
			PropertyPkgID,
			pkg.ID,
		},
		{
			PropertyPkgType,
			pkgType,
		},
		{
			PropertyFilePath,
			pkg.FilePath,
		},
		{
			PropertySrcName,
			pkg.SrcName,
		},
		{
			PropertySrcVersion,
			pkg.SrcVersion,
		},
		{
			PropertySrcRelease,
			pkg.SrcRelease,
		},
		{
			PropertySrcEpoch,
			strconv.Itoa(pkg.SrcEpoch),
		},
		{
			PropertyModularitylabel,
			pkg.Modularitylabel,
		},
		{
			PropertyLayerDigest,
			pkg.Layer.Digest,
		},
		{
			PropertyLayerDiffID,
			pkg.Layer.DiffID,
		},
	}

	var properties []cdx.Property
	for _, prop := range props {
		properties = appendProperties(properties, prop.name, prop.value)
	}
	if len(properties) == 0 {
		return nil
	}

	return &properties
}

func appendProperties(properties []cdx.Property, key, value string) []cdx.Property {
	if value == "" || (key == PropertySrcEpoch && value == "0") {
		return properties
	}
	return append(properties, cdxProperty(key, value))
}

func cdxProperty(key, value string) cdx.Property {
	return cdx.Property{
		Name:  Namespace + key,
		Value: value,
	}
}

func cdxAdvisories(refs []string) *[]cdx.Advisory {
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

func cdxRatings(vulnerability types.DetectedVulnerability) *[]cdx.VulnerabilityRating {
	rates := make([]cdx.VulnerabilityRating, 0) // To export an empty array in JSON
	for sourceID, severity := range vulnerability.VendorSeverity {
		// When the vendor also provides CVSS score/vector
		if cvss, ok := vulnerability.CVSS[sourceID]; ok {
			if cvss.V2Score != 0 || cvss.V2Vector != "" {
				rates = append(rates, cdxRatingV2(sourceID, severity, cvss))
			}
			if cvss.V3Score != 0 || cvss.V3Vector != "" {
				rates = append(rates, cdxRatingV3(sourceID, severity, cvss))
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

func cdxRatingV2(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
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

func cdxRatingV3(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
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

func cdxSource(source *dtypes.DataSource) *cdx.Source {
	if source == nil {
		return nil
	}

	return &cdx.Source{
		Name: string(source.ID),
		URL:  source.URL,
	}
}

func cdxAffects(ref, version string) cdx.Affects {
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
