package core

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"k8s.io/utils/clock"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	ToolVendor = "aquasecurity"
	ToolName   = "trivy"
	Namespace  = ToolVendor + ":" + ToolName + ":"

	// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
	timeLayout = "2006-01-02T15:04:05+00:00"
)

type NewUUID func() uuid.UUID

type Option func(dx *CycloneDX)

func WithClock(clock clock.Clock) Option {
	return func(opts *CycloneDX) {
		opts.clock = clock
	}
}

func WithNewUUID(newUUID NewUUID) Option {
	return func(opts *CycloneDX) {
		opts.newUUID = newUUID
	}
}

type CycloneDX struct {
	appVersion string
	clock      clock.Clock
	newUUID    NewUUID
}

type Component struct {
	Type       cdx.ComponentType
	Name       string
	Group      string
	Version    string
	PackageURL *purl.PackageURL
	Licenses   []string
	Hashes     []digest.Digest
	Supplier   string
	Properties []Property

	Components      []*Component
	Vulnerabilities []types.DetectedVulnerability
}

type Property struct {
	Name      string
	Value     string
	Namespace string
}

func NewCycloneDX(version string, opts ...Option) *CycloneDX {
	c := &CycloneDX{
		appVersion: version,
		clock:      clock.RealClock{},
		newUUID:    uuid.New,
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *CycloneDX) Marshal(root *Component) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SerialNumber = c.newUUID().URN()
	bom.Metadata = c.Metadata()

	components := map[string]*cdx.Component{}
	dependencies := map[string]*[]string{}
	vulnerabilities := map[string]*cdx.Vulnerability{}
	bom.Metadata.Component = c.MarshalComponent(root, components, dependencies, vulnerabilities)

	// Remove metadata component
	delete(components, bom.Metadata.Component.BOMRef)

	bom.Components = c.Components(components)
	bom.Dependencies = c.Dependencies(dependencies)
	bom.Vulnerabilities = c.Vulnerabilities(vulnerabilities)

	return bom
}

func (c *CycloneDX) MarshalComponent(component *Component, components map[string]*cdx.Component,
	deps map[string]*[]string, vulns map[string]*cdx.Vulnerability) *cdx.Component {
	bomRef := c.BOMRef(component)

	// When multiple lock files have the same dependency with the same name and version,
	// "BOM-Ref" (PURL technically) of "Library" components may conflict.
	// In that case, only one "Library" component will be added and
	// some "Application" components will refer to the same component.
	// e.g.
	//    Application component (/app1/package-lock.json)
	//    |
	//    |    Application component (/app2/package-lock.json)
	//    |    |
	//    └----┴----> Library component (npm package, express-4.17.3)
	//
	if v, ok := components[bomRef]; ok {
		return v
	}

	cdxComponent := &cdx.Component{
		BOMRef:     bomRef,
		Type:       component.Type,
		Name:       component.Name,
		Group:      component.Group,
		Version:    component.Version,
		PackageURL: c.PackageURL(component.PackageURL),
		Supplier:   c.Supplier(component.Supplier),
		Hashes:     c.Hashes(component.Hashes),
		Licenses:   c.Licenses(component.Licenses),
		Properties: lo.ToPtr(c.Properties(component.Properties)),
	}
	components[cdxComponent.BOMRef] = cdxComponent

	for _, v := range component.Vulnerabilities {
		// If the same vulnerability affects multiple packages, those packages will be aggregated into one vulnerability.
		//   Vulnerability component (CVE-2020-26247)
		//     -> Library component (nokogiri /srv/app1/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
		//     -> Library component (nokogiri /srv/app2/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
		if vuln, ok := vulns[v.VulnerabilityID]; ok {
			*vuln.Affects = append(*vuln.Affects, cdxAffects(bomRef, v.InstalledVersion))
			if v.FixedVersion != "" {
				// new recommendation
				rec := fmt.Sprintf("Upgrade %s to version %s", v.PkgName, v.FixedVersion)
				// previous recommendations
				recs := strings.Split(vuln.Recommendation, "; ")
				if !slices.Contains(recs, rec) {
					recs = append(recs, rec)
					slices.Sort(recs)
					vuln.Recommendation = strings.Join(recs, "; ")
				}
			}
		} else {
			vulns[v.VulnerabilityID] = c.marshalVulnerability(cdxComponent.BOMRef, v)
		}
	}

	dependencies := make([]string, 0) // Components that do not have their own dependencies must be declared as empty elements
	for _, child := range component.Components {
		childComponent := c.MarshalComponent(child, components, deps, vulns)
		dependencies = append(dependencies, childComponent.BOMRef)
	}
	sort.Strings(dependencies)

	deps[cdxComponent.BOMRef] = &dependencies

	return cdxComponent
}

func (c *CycloneDX) marshalVulnerability(bomRef string, vuln types.DetectedVulnerability) *cdx.Vulnerability {
	v := &cdx.Vulnerability{
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

func (c *CycloneDX) BOMRef(component *Component) string {
	// PURL takes precedence over UUID
	if component.PackageURL == nil {
		return c.newUUID().String()
	}
	return component.PackageURL.BOMRef()
}

func (c *CycloneDX) Metadata() *cdx.Metadata {
	return &cdx.Metadata{
		Timestamp: c.clock.Now().UTC().Format(timeLayout),
		Tools: &[]cdx.Tool{
			{
				Vendor:  ToolVendor,
				Name:    ToolName,
				Version: c.appVersion,
			},
		},
	}
}

func (c *CycloneDX) Components(uniq map[string]*cdx.Component) *[]cdx.Component {
	// Convert components from map to slice and sort by BOM-Ref
	components := lo.MapToSlice(uniq, func(_ string, value *cdx.Component) cdx.Component {
		return *value
	})
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})
	return &components
}

func (c *CycloneDX) Dependencies(uniq map[string]*[]string) *[]cdx.Dependency {
	// Convert dependencies from map to slice and sort by BOM-Ref
	dependencies := lo.MapToSlice(uniq, func(bomRef string, value *[]string) cdx.Dependency {
		return cdx.Dependency{
			Ref:          bomRef,
			Dependencies: value,
		}
	})
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Ref < dependencies[j].Ref
	})
	return &dependencies
}

func (c *CycloneDX) Vulnerabilities(uniq map[string]*cdx.Vulnerability) *[]cdx.Vulnerability {
	vulns := lo.MapToSlice(uniq, func(bomRef string, value *cdx.Vulnerability) cdx.Vulnerability {
		sort.Slice(*value.Affects, func(i, j int) bool {
			return (*value.Affects)[i].Ref < (*value.Affects)[j].Ref
		})
		return *value
	})
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].BOMRef < vulns[j].BOMRef
	})
	return &vulns
}

func (c *CycloneDX) PackageURL(purl *purl.PackageURL) string {
	if purl == nil {
		return ""
	}
	return purl.String()
}

func (c *CycloneDX) Supplier(supplier string) *cdx.OrganizationalEntity {
	if supplier == "" {
		return nil
	}
	return &cdx.OrganizationalEntity{
		Name: supplier,
	}
}

func (c *CycloneDX) Hashes(hashes []digest.Digest) *[]cdx.Hash {
	if len(hashes) == 0 {
		return nil
	}
	var cdxHashes []cdx.Hash
	for _, hash := range hashes {
		var alg cdx.HashAlgorithm
		switch hash.Algorithm() {
		case digest.SHA1:
			alg = cdx.HashAlgoSHA1
		case digest.SHA256:
			alg = cdx.HashAlgoSHA256
		case digest.MD5:
			alg = cdx.HashAlgoMD5
		default:
			log.Logger.Debugf("Unable to convert %q algorithm to CycloneDX format", hash.Algorithm())
			continue
		}

		cdxHashes = append(cdxHashes, cdx.Hash{
			Algorithm: alg,
			Value:     hash.Encoded(),
		})
	}
	return &cdxHashes
}

func (c *CycloneDX) Licenses(licenses []string) *cdx.Licenses {
	if len(licenses) == 0 {
		return nil
	}
	choices := lo.Map(licenses, func(license string, i int) cdx.LicenseChoice {
		return cdx.LicenseChoice{Expression: license}
	})
	return lo.ToPtr(cdx.Licenses(choices))
}

func (c *CycloneDX) Properties(properties []Property) []cdx.Property {
	cdxProps := make([]cdx.Property, 0, len(properties))
	for _, property := range properties {
		namespace := Namespace
		if len(property.Namespace) > 0 {
			namespace = property.Namespace
		}
		cdxProps = append(cdxProps,
			cdx.Property{
				Name:  namespace + property.Name,
				Value: property.Value,
			})
	}
	sort.Slice(cdxProps, func(i, j int) bool {
		return cdxProps[i].Name < cdxProps[j].Name
	})
	return cdxProps
}

func IsTrivySBOM(c *cdx.BOM) bool {
	if c == nil || c.Metadata == nil || c.Metadata.Tools == nil {
		return false
	}

	for _, tool := range *c.Metadata.Tools {
		if tool.Vendor == ToolVendor && tool.Name == ToolName {
			return true
		}
	}
	return false
}

func LookupProperty(properties *[]cdx.Property, key string) string {
	for _, p := range lo.FromPtr(properties) {
		if p.Name == Namespace+key {
			return p.Value
		}
	}
	return ""
}

func UnmarshalProperties(properties *[]cdx.Property) map[string]string {
	props := map[string]string{}
	for _, prop := range lo.FromPtr(properties) {
		if !strings.HasPrefix(prop.Name, Namespace) {
			continue
		}
		props[strings.TrimPrefix(prop.Name, Namespace)] = prop.Value
	}
	return props
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
