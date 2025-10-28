package cyclonedx

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

const (
	ToolVendor       = "aquasecurity"
	ToolName         = "trivy"
	ToolManufacturer = "Aqua Security Software Ltd."
	Namespace        = ToolVendor + ":" + ToolName + ":"

	// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
	timeLayout = "2006-01-02T15:04:05+00:00"
)

type Marshaler struct {
	appVersion   string // Trivy version
	bom          *core.BOM
	componentIDs map[uuid.UUID]string

	logger *log.Logger
}

func NewMarshaler(version string) Marshaler {
	return Marshaler{
		appVersion: version,
		logger:     log.WithPrefix(log.PrefixCycloneDX),
	}
}

// MarshalReport converts the Trivy report to the CycloneDX format
func (m *Marshaler) MarshalReport(ctx context.Context, report types.Report) (*cdx.BOM, error) {
	// Convert into an intermediate representation
	bom, err := sbomio.NewEncoder(sbomio.WithBOMRef()).Encode(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal report: %w", err)
	}

	return m.Marshal(ctx, bom)
}

// Marshal converts the Trivy component to the CycloneDX format
func (m *Marshaler) Marshal(ctx context.Context, bom *core.BOM) (*cdx.BOM, error) {
	m.bom = bom
	m.componentIDs = make(map[uuid.UUID]string, len(m.bom.Components()))

	cdxBOM := cdx.NewBOM()
	cdxBOM.SerialNumber = uuid.New().URN()
	cdxBOM.Metadata = m.Metadata(ctx)

	var err error
	if cdxBOM.Metadata.Component, err = m.MarshalRoot(); err != nil {
		return nil, xerrors.Errorf("failed to marshal component: %w", err)
	}

	if cdxBOM.Components, err = m.marshalComponents(); err != nil {
		return nil, xerrors.Errorf("failed to marshal components: %w", err)
	}

	cdxBOM.Dependencies = m.marshalDependencies()
	cdxBOM.Vulnerabilities = m.marshalVulnerabilities()

	return cdxBOM, nil
}

func (m *Marshaler) Metadata(ctx context.Context) *cdx.Metadata {
	return &cdx.Metadata{
		Timestamp: clock.Now(ctx).UTC().Format(timeLayout),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:         cdx.ComponentTypeApplication,
					Group:        ToolVendor,
					Name:         ToolName,
					Version:      m.appVersion,
					Manufacturer: &cdx.OrganizationalEntity{Name: ToolManufacturer},
				},
			},
		},
	}
}

func (m *Marshaler) MarshalRoot() (*cdx.Component, error) {
	return m.MarshalComponent(m.bom.Root())
}

func (m *Marshaler) MarshalComponent(component *core.Component) (*cdx.Component, error) {
	componentType, err := m.componentType(component.Type)
	if err != nil {
		return nil, xerrors.Errorf("failed to get cdx component type: %w", err)
	}

	cdxComponent := &cdx.Component{
		BOMRef:     component.PkgIdentifier.BOMRef,
		Type:       componentType,
		Name:       component.Name,
		Group:      component.Group,
		Version:    component.Version,
		PackageURL: m.PackageURL(component.PkgIdentifier.PURL),
		Supplier:   m.Supplier(component.Supplier),
		Hashes:     m.Hashes(component.Files),
		Licenses:   m.Licenses(component.Licenses),
		Properties: m.Properties(component.Properties),
	}
	m.componentIDs[component.ID()] = cdxComponent.BOMRef

	return cdxComponent, nil
}

func (m *Marshaler) marshalComponents() (*[]cdx.Component, error) {
	var cdxComponents []cdx.Component
	for _, component := range m.bom.Components() {
		if component.Root {
			continue
		}
		c, err := m.MarshalComponent(component)
		if err != nil {
			return nil, xerrors.Errorf("failed to marshal component: %w", err)
		}
		cdxComponents = append(cdxComponents, *c)
	}

	// CycloneDX requires an empty slice rather than a nil slice
	if len(cdxComponents) == 0 {
		return &[]cdx.Component{}, nil
	}

	// Sort components by BOM-Ref
	sort.Slice(cdxComponents, func(i, j int) bool {
		return cdxComponents[i].BOMRef < cdxComponents[j].BOMRef
	})
	return &cdxComponents, nil
}

func (m *Marshaler) marshalDependencies() *[]cdx.Dependency {
	var dependencies []cdx.Dependency
	for key, rels := range m.bom.Relationships() {
		ref, ok := m.componentIDs[key]
		if !ok {
			continue
		}

		deps := lo.FilterMap(rels, func(rel core.Relationship, _ int) (string, bool) {
			d, ok := m.componentIDs[rel.Dependency]
			return d, ok
		})
		sort.Strings(deps)

		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &deps,
		})
	}

	// Sort dependencies by BOM-Ref
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Ref < dependencies[j].Ref
	})
	return &dependencies
}

func (m *Marshaler) marshalVulnerabilities() *[]cdx.Vulnerability {
	vulns := make(map[string]*cdx.Vulnerability)
	for id, vv := range m.bom.Vulnerabilities() {
		bomRef := m.componentIDs[id]
		for _, v := range vv {
			// If the same vulnerability affects multiple packages, those packages will be aggregated into one vulnerability.
			//   Vulnerability component (CVE-2020-26247)
			//     -> Library component (nokogiri /srv/app1/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
			//     -> Library component (nokogiri /srv/app2/vendor/bundle/ruby/3.0.0/specifications/nokogiri-1.10.0.gemspec)
			if vuln, ok := vulns[v.ID]; ok {
				*vuln.Affects = append(*vuln.Affects, m.affects(bomRef, v.InstalledVersion))
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
				vulns[v.ID] = m.marshalVulnerability(bomRef, v)
			}
		}
	}

	vulnList := lo.MapToSlice(vulns, func(_ string, value *cdx.Vulnerability) cdx.Vulnerability {
		sort.Slice(*value.Affects, func(i, j int) bool {
			return (*value.Affects)[i].Ref < (*value.Affects)[j].Ref
		})
		return *value
	})
	sort.Slice(vulnList, func(i, j int) bool {
		return vulnList[i].ID < vulnList[j].ID
	})
	return &vulnList
}

// componentType converts the Trivy component type to the CycloneDX component type
func (*Marshaler) componentType(t core.ComponentType) (cdx.ComponentType, error) {
	switch t {
	case core.TypeContainerImage, core.TypeVM:
		return cdx.ComponentTypeContainer, nil
	case core.TypeApplication, core.TypeFilesystem, core.TypeRepository:
		return cdx.ComponentTypeApplication, nil
	case core.TypeLibrary:
		return cdx.ComponentTypeLibrary, nil
	case core.TypeOS:
		return cdx.ComponentTypeOS, nil
	case core.TypePlatform:
		return cdx.ComponentTypePlatform, nil
	}
	return "", xerrors.Errorf("unknown component type: %s", t)
}

func (*Marshaler) PackageURL(p *packageurl.PackageURL) string {
	if p == nil {
		return ""
	}
	return p.String()
}

func (*Marshaler) Supplier(supplier string) *cdx.OrganizationalEntity {
	if supplier == "" {
		return nil
	}
	return &cdx.OrganizationalEntity{
		Name: supplier,
	}
}

func (m *Marshaler) Hashes(files []core.File) *[]cdx.Hash {
	digests := lo.FlatMap(files, func(file core.File, _ int) []digest.Digest {
		return file.Digests
	})
	if len(digests) == 0 {
		return nil
	}

	var cdxHashes []cdx.Hash
	for _, d := range digests {
		var alg cdx.HashAlgorithm
		switch d.Algorithm() {
		case digest.SHA1:
			alg = cdx.HashAlgoSHA1
		case digest.SHA256:
			alg = cdx.HashAlgoSHA256
		case digest.SHA512:
			alg = cdx.HashAlgoSHA512
		case digest.MD5:
			alg = cdx.HashAlgoMD5
		default:
			m.logger.Debug("Unable to convert algorithm to CycloneDX format", log.Any("alg", d.Algorithm()))
			continue
		}

		cdxHashes = append(cdxHashes, cdx.Hash{
			Algorithm: alg,
			Value:     d.Encoded(),
		})
	}
	return &cdxHashes
}

func (m *Marshaler) Licenses(licenses []string) *cdx.Licenses {
	licenses = lo.Compact(licenses)
	if len(licenses) == 0 {
		return nil
	}
	return m.normalizeLicenses(licenses)
}

func (m *Marshaler) normalizeLicenses(licenses []string) *cdx.Licenses {
	expressions := lo.Map(licenses, func(license string, _ int) expression.Expression {
		return m.normalizeLicense(license)
	})
	// Check if all licenses are valid SPDX expressions
	allValidSPDX := lo.EveryBy(expressions, func(expr expression.Expression) bool {
		return expr.IsSPDXExpression()
	})

	// Check if at least one is a CompoundExpr
	hasCompoundExpr := lo.ContainsBy(expressions, func(expr expression.Expression) bool {
		_, isCompound := expr.(expression.CompoundExpr)
		return isCompound
	})

	// If all are valid SPDX AND at least one contains CompoundExpr, combine into single Expression
	if allValidSPDX && hasCompoundExpr {
		exprStrs := lo.Map(expressions, func(expr expression.Expression, _ int) string {
			return expr.String()
		})
		return &cdx.Licenses{{Expression: strings.Join(exprStrs, " AND ")}}
	}

	// Otherwise use individual LicenseChoice entries with license.id or license.name
	choices := lo.Map(expressions, func(expr expression.Expression, _ int) cdx.LicenseChoice {
		if s, ok := expr.(expression.SimpleExpr); ok && s.IsSPDXExpression() {
			// Use license.id for valid SPDX ID (e.g., "MIT", "Apache-2.0")
			return cdx.LicenseChoice{License: &cdx.License{ID: s.String()}}
		}
		// Use license.name for everything else (invalid SPDX ID, SPDX expression, etc.)
		return cdx.LicenseChoice{License: &cdx.License{Name: expr.String()}}
	})
	return lo.ToPtr(cdx.Licenses(choices))
}

func (m *Marshaler) normalizeLicense(license string) expression.Expression {
	// Save text license as licenseChoice.license.name
	if after, ok := strings.CutPrefix(license, licensing.LicenseTextPrefix); ok {
		return expression.SimpleExpr{
			License: after,
		}
	}

	// e.g. GPL-3.0-with-autoconf-exception
	license = strings.ReplaceAll(license, "-with-", " WITH ")
	license = strings.ReplaceAll(license, "-WITH-", " WITH ")

	normalizedLicenses, err := expression.Normalize(license, licensing.NormalizeLicense, expression.NormalizeForSPDX)
	if err != nil {
		// Not fail on the invalid license
		m.logger.Warn("Unable to marshal SPDX licenses", log.String("license", license))
		return expression.SimpleExpr{License: license}
	}

	return normalizedLicenses
}

func (*Marshaler) Properties(properties []core.Property) *[]cdx.Property {
	cdxProps := make([]cdx.Property, 0, len(properties))
	for _, property := range properties {
		namespace := cmp.Or(property.Namespace, Namespace)

		// External property preserves original name, Trivy property gets namespace prefix
		name := lo.Ternary(property.External, property.Name, namespace+property.Name)

		cdxProps = append(cdxProps, cdx.Property{
			Name:  name,
			Value: property.Value,
		})
	}
	sort.Slice(cdxProps, func(i, j int) bool {
		if cdxProps[i].Name != cdxProps[j].Name {
			return cdxProps[i].Name < cdxProps[j].Name
		}
		return cdxProps[i].Value < cdxProps[j].Value
	})
	return &cdxProps
}

func (*Marshaler) affects(ref, version string) cdx.Affects {
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

func (*Marshaler) advisories(refs []string) *[]cdx.Advisory {
	refs = lo.Uniq(refs)
	advs := lo.FilterMap(refs, func(ref string, _ int) (cdx.Advisory, bool) {
		// There are cases when `ref` contains extra info
		// But we need to use only URL.
		// cf. https://github.com/aquasecurity/trivy/issues/6801
		ref = trimNonUrlInfo(ref)
		return cdx.Advisory{URL: ref}, ref != ""
	})

	// cyclonedx converts link to empty `[]cdx.Advisory` to `null`
	// `bom-1.5.schema.json` doesn't support this - `Invalid type. Expected: array, given: null`
	// we need to explicitly set `nil` for empty `refs` slice
	if len(advs) == 0 {
		return nil
	}

	return &advs
}

// trimNonUrlInfo returns first valid URL.
func trimNonUrlInfo(ref string) string {
	ss := strings.SplitSeq(ref, " ")
	for s := range ss {
		if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
			return s
		}
	}
	return ""
}

func (m *Marshaler) marshalVulnerability(bomRef string, vuln core.Vulnerability) *cdx.Vulnerability {
	v := &cdx.Vulnerability{
		ID:          vuln.ID,
		Source:      m.source(vuln.DataSource),
		Ratings:     m.ratings(vuln),
		CWEs:        m.cwes(vuln.CweIDs),
		Description: vuln.Description,
		Advisories:  m.advisories(append([]string{vuln.PrimaryURL}, vuln.References...)),
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

	v.Affects = &[]cdx.Affects{m.affects(bomRef, vuln.InstalledVersion)}

	return v
}

func (*Marshaler) source(source *dtypes.DataSource) *cdx.Source {
	if source == nil {
		return nil
	}

	return &cdx.Source{
		Name: string(source.ID),
		URL:  source.URL,
	}
}

func (m *Marshaler) cwes(cweIDs []string) *[]int {
	// to skip cdx.Vulnerability.CWEs when generating json
	// we should return 'clear' nil without 'type' interface part
	if cweIDs == nil {
		return nil
	}
	var ret []int
	for _, cweID := range cweIDs {
		number, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(cweID), "cwe-"))
		if err != nil {
			m.logger.Debug("CWE-ID parse error", log.Err(err))
			continue
		}
		ret = append(ret, number)
	}
	return &ret
}

func (m *Marshaler) ratings(vuln core.Vulnerability) *[]cdx.VulnerabilityRating {
	rates := make([]cdx.VulnerabilityRating, 0) // nolint:gocritic // To export an empty array in JSON
	for sourceID, severity := range vuln.VendorSeverity {
		// When the vendor also provides CVSS score/vector
		if cvss, ok := vuln.CVSS[sourceID]; ok {
			if cvss.V2Score != 0 || cvss.V2Vector != "" {
				rates = append(rates, m.ratingV2(sourceID, severity, cvss))
			}
			if cvss.V3Score != 0 || cvss.V3Vector != "" {
				rates = append(rates, m.ratingV3(sourceID, severity, cvss))
			}
		} else { // When the vendor provides only severity
			rate := cdx.VulnerabilityRating{
				Source: &cdx.Source{
					Name: string(sourceID),
				},
				Severity: m.severity(severity),
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

func (m *Marshaler) ratingV2(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	cdxSeverity := m.severity(severity)

	// Trivy keeps only CVSSv3 severity for NVD.
	// The CVSSv2 severity must be calculated according to CVSSv2 score.
	if sourceID == vulnerability.NVD {
		cdxSeverity = m.nvdSeverityV2(cvss.V2Score)
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

func (m *Marshaler) ratingV3(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	rate := cdx.VulnerabilityRating{
		Source: &cdx.Source{
			Name: string(sourceID),
		},
		Score:    &cvss.V3Score,
		Method:   cdx.ScoringMethodCVSSv3,
		Severity: m.severity(severity),
		Vector:   cvss.V3Vector,
	}
	if strings.HasPrefix(cvss.V3Vector, "CVSS:3.1") {
		rate.Method = cdx.ScoringMethodCVSSv31
	}
	return rate
}

// severity converts the Trivy severity to the CycloneDX severity
func (*Marshaler) severity(s dtypes.Severity) cdx.Severity {
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

func (*Marshaler) nvdSeverityV2(score float64) cdx.Severity {
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
