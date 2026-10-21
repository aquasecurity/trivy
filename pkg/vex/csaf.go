package vex

import (
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"

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
	if vuln.VulnerabilityID == "" {
		return types.ModifiedFinding{}, false
	}

	// The same vulnerability ID can appear in several entries, so check all of them.
	for _, item := range v.advisory.Vulnerabilities {
		if !matchVulnerabilityID(item, vuln.VulnerabilityID) {
			continue
		}
		if status := v.match(item, product, subProduct, vuln.VulnerabilityID); status != "" {
			return types.NewModifiedFinding(vuln, status, v.statement(item), v.source), true
		}
	}
	return types.ModifiedFinding{}, false
}

// matchVulnerabilityID checks whether the CSAF vulnerability is identified by the given ID,
// either through the CVE field or through any of the IDs.
func matchVulnerabilityID(item *csaf.Vulnerability, vulnID string) bool {
	if item == nil {
		return false
	}
	if item.CVE != nil && strings.EqualFold(string(*item.CVE), vulnID) {
		return true
	}
	return lo.ContainsBy(item.IDs, func(id *csaf.VulnerabilityID) bool {
		return id != nil && id.Text != nil && strings.EqualFold(string(*id.Text), vulnID)
	})
}

func (v *CSAF) match(vuln *csaf.Vulnerability, product, subProduct *core.Component, vulnId string) types.FindingStatus {
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
			logger := v.logger.With(log.String("vulnerability-id", vulnId),
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
	for _, productPURL := range v.productPURLs(productID) {
		if productPURL.Match(product.PkgIdentifier.PURL) {
			return true
		}
	}
	return false
}

func (v *CSAF) matchRelationship(fullProductID csaf.ProductID, product, subProduct *core.Component) (
	csaf.RelationshipCategory, bool) {

	// A relationship describes a sub-component within a product, so it can only match
	// when a sub-component is given. subProduct is nil when a component is evaluated
	// on its own (see reachRoot).
	if subProduct == nil {
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
	return v.purlsFromProductIdentificationHelpers(v.advisory.ProductTree.CollectProductIdentificationHelpers(product))
}

// inspectProductRelationships returns a map of PackageURLs associated to each relationship category
// iterating over relationships looking for sub-products that might be part of the original product
func (v *CSAF) inspectProductRelationships(fullProductID csaf.ProductID) map[csaf.RelationshipCategory][]relationship {
	if v.advisory.ProductTree.RelationShips == nil {
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
		return lo.FromPtr(threat.Category) == csaf.CSAFThreatCategoryImpact
	})
	if !ok {
		return ""
	}
	return lo.FromPtr(threat.Details)
}
