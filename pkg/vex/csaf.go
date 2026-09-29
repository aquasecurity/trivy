package vex

import (
	"math"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type CSAF struct {
	advisory csaf.Advisory
	source   string
	logger   *log.Logger
}

type relationship struct {
	Product     *purl.PackageURL
	SubProducts []*purl.PackageURL
}

func newCSAF(advisory csaf.Advisory, source string) *CSAF {
	return &CSAF{
		advisory: advisory,
		source:   source,
		logger:   log.WithPrefix("vex").With(log.String("format", "CSAF")),
	}
}

func (v *CSAF) Filter(result *types.Result, bom *core.BOM) {
	filterVulnerabilities(result, bom, v.NotAffected)
}

func (v *CSAF) NotAffected(vuln types.DetectedVulnerability, product, subProduct *core.Component) (types.ModifiedFinding, bool) {
	found, ok := v.findVulnerability(vuln.VulnerabilityID)
	if !ok {
		return types.ModifiedFinding{}, false
	}

	status := v.match(found, product, subProduct)
	if status == "" {
		return types.ModifiedFinding{}, false
	}
	return types.NewModifiedFinding(vuln, status, v.statement(found), v.source), true
}

// Rescore returns the severity and CVSS of the first usable score applicable to the product.
// Scores apply only to the products they list, either directly or via product relationships.
func (v *CSAF) Rescore(vuln types.DetectedVulnerability, product, subProduct *core.Component) (SeverityOverride, bool) {
	found, ok := v.findVulnerability(vuln.VulnerabilityID)
	if !ok {
		return SeverityOverride{}, false
	}

	for _, score := range found.Scores {
		if score == nil || !v.matchScore(score, product, subProduct) {
			continue
		}
		if override, ok := extractSeverityOverride(score); ok {
			override.Source = CSAFSeveritySource
			override.Document = v.source
			return override, true
		}
	}
	return SeverityOverride{}, false
}

func (v *CSAF) match(vuln *csaf.Vulnerability, product, subProduct *core.Component) types.FindingStatus {
	if product == nil || product.PkgIdentifier.PURL == nil || vuln.ProductStatus == nil {
		return ""
	}

	productStatusMap := map[types.FindingStatus]csaf.Products{
		types.FindingStatusNotAffected: lo.FromPtr(vuln.ProductStatus.KnownNotAffected),
		types.FindingStatusFixed:       lo.FromPtr(vuln.ProductStatus.Fixed),
	}
	for status, productRange := range productStatusMap {
		for _, p := range productRange {
			productID := lo.FromPtr(p)
			logger := v.logger.With(log.String("vulnerability-id", string(*vuln.CVE)),
				log.String("product-id", string(productID)), log.String("status", string(status)))

			// Check if the product is affected
			if v.matchProduct(productID, product) {
				logger.Info("Filtered out the detected vulnerability")
				return status
			}

			// Check if the relationship between the product and the subcomponent is affected
			if category, match := v.matchRelationship(productID, product, subProduct); match {
				logger.Info("Filtered out the detected vulnerability",
					log.String("relationship", string(category)))
				return status
			}
		}
	}
	return ""
}

func (v *CSAF) matchProduct(productID csaf.ProductID, product *core.Component) bool {
	if product == nil || product.PkgIdentifier.PURL == nil {
		return false
	}
	for _, productPURL := range v.productPURLs(productID) {
		if productPURL.Match(product.PkgIdentifier.PURL) {
			return true
		}
	}
	return false
}

func (v *CSAF) matchRelationship(fullProductID csaf.ProductID, product, subProduct *core.Component) (
	csaf.RelationshipCategory, bool) {
	if product == nil || product.PkgIdentifier.PURL == nil || subProduct == nil || subProduct.PkgIdentifier.PURL == nil {
		return "", false
	}

	for category, relationships := range v.inspectProductRelationships(fullProductID) {
		for _, rel := range relationships {
			if !rel.Product.Match(product.PkgIdentifier.PURL) {
				continue
			}
			for _, subProductPURL := range rel.SubProducts {
				if subProductPURL.Match(subProduct.PkgIdentifier.PURL) {
					return category, true
				}
			}
		}
	}
	return "", false
}

// productPURLs returns a slice of PackageURLs associated to a given product
func (v *CSAF) productPURLs(product csaf.ProductID) []*purl.PackageURL {
	if v.advisory.ProductTree == nil {
		return nil
	}
	return v.purlsFromProductIdentificationHelpers(v.advisory.ProductTree.CollectProductIdentificationHelpers(product))
}

// inspectProductRelationships returns a map of PackageURLs associated to each relationship category
// iterating over relationships looking for sub-products that might be part of the original product
func (v *CSAF) inspectProductRelationships(fullProductID csaf.ProductID) map[csaf.RelationshipCategory][]relationship {
	if v.advisory.ProductTree == nil || v.advisory.ProductTree.RelationShips == nil {
		return nil
	}

	relationships := make(map[csaf.RelationshipCategory][]relationship)
	for _, rel := range lo.FromPtr(v.advisory.ProductTree.RelationShips) {
		if rel == nil || rel.FullProductName == nil {
			continue
		} else if lo.FromPtr(rel.FullProductName.ProductID) != fullProductID {
			continue
		}

		category := lo.FromPtr(rel.Category)
		switch category {
		case csaf.CSAFRelationshipCategoryDefaultComponentOf,
			csaf.CSAFRelationshipCategoryInstalledOn,
			csaf.CSAFRelationshipCategoryInstalledWith:

			productID := lo.FromPtr(rel.RelatesToProductReference)
			productPURLs := v.productPURLs(productID)

			subProductID := lo.FromPtr(rel.ProductReference)
			subProductPURLs := v.productPURLs(subProductID)

			for _, productPURL := range productPURLs {
				relationships[category] = append(relationships[category], relationship{
					Product:     productPURL,
					SubProducts: subProductPURLs,
				})
			}
		}
	}

	return relationships
}

// purlsFromProductIdentificationHelpers returns a slice of PURLs given a slice of ProductIdentificationHelpers.
func (v *CSAF) purlsFromProductIdentificationHelpers(helpers []*csaf.ProductIdentificationHelper) []*purl.PackageURL {
	return lo.FilterMap(helpers, func(helper *csaf.ProductIdentificationHelper, _ int) (*purl.PackageURL, bool) {
		if helper == nil || helper.PURL == nil {
			return nil, false
		}
		p, err := purl.FromString(string(*helper.PURL))
		if err != nil {
			v.logger.Error("Invalid PURL", log.String("purl", string(*helper.PURL)), log.Err(err))
			return nil, false
		}
		return p, true
	})
}

func (v *CSAF) statement(vuln *csaf.Vulnerability) string {
	threat, ok := lo.Find(vuln.Threats, func(threat *csaf.Threat) bool {
		return threat != nil && lo.FromPtr(threat.Category) == csaf.CSAFThreatCategoryImpact
	})
	if !ok {
		return ""
	}
	return lo.FromPtr(threat.Details)
}

func (v *CSAF) findVulnerability(vulnID string) (*csaf.Vulnerability, bool) {
	return lo.Find(v.advisory.Vulnerabilities, func(item *csaf.Vulnerability) bool {
		return item != nil && item.CVE != nil && string(*item.CVE) == vulnID
	})
}

func (v *CSAF) matchScore(score *csaf.Score, product, subProduct *core.Component) bool {
	for _, p := range lo.FromPtr(score.Products) {
		productID := lo.FromPtr(p)
		if subProduct == nil && v.matchProduct(productID, product) {
			return true
		}
		if _, match := v.matchRelationship(productID, product, subProduct); match {
			return true
		}
	}
	return false
}

// extractSeverityOverride prefers CVSS v3 over CVSS v2. Scores without a valid base score are ignored.
func extractSeverityOverride(score *csaf.Score) (SeverityOverride, bool) {
	if score.CVSS3 != nil && score.CVSS3.BaseScore != nil {
		baseScore := *score.CVSS3.BaseScore
		severity, ok := parseCVSSSeverity(string(lo.FromPtr(score.CVSS3.BaseSeverity)))
		if ok && !math.IsNaN(baseScore) && !math.IsInf(baseScore, 0) && baseScore >= 0 && baseScore <= 10 {
			return SeverityOverride{
				Severity: severity,
				CVSS: dbTypes.CVSS{
					V3Vector: string(lo.FromPtr(score.CVSS3.VectorString)),
					V3Score:  baseScore,
				},
			}, true
		}
	}

	if score.CVSS2 != nil && score.CVSS2.BaseScore != nil {
		baseScore := *score.CVSS2.BaseScore
		if !math.IsNaN(baseScore) && !math.IsInf(baseScore, 0) && baseScore >= 0 && baseScore <= 10 {
			return SeverityOverride{
				Severity: cvss2Severity(baseScore),
				CVSS: dbTypes.CVSS{
					V2Vector: string(lo.FromPtr(score.CVSS2.VectorString)),
					V2Score:  baseScore,
				},
			}, true
		}
	}

	return SeverityOverride{}, false
}

// cvss2Severity calculates the severity from the CVSS v2 score as CVSS v2 has no qualitative rating.
func cvss2Severity(score float64) dbTypes.Severity {
	switch {
	case score == 0:
		return dbTypes.SeverityUnknown
	case score < 4:
		return dbTypes.SeverityLow
	case score < 7:
		return dbTypes.SeverityMedium
	default:
		return dbTypes.SeverityHigh
	}
}
