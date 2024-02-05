package vex

import (
	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"go.uber.org/zap"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

type CSAF struct {
	advisory csaf.Advisory
	logger   *zap.SugaredLogger
}

func newCSAF(advisory csaf.Advisory) VEX {
	return &CSAF{
		advisory: advisory,
		logger:   log.Logger.With(zap.String("VEX format", "CSAF")),
	}
}

func (v *CSAF) Filter(vulns []types.DetectedVulnerability) []types.DetectedVulnerability {
	return lo.Filter(vulns, func(vuln types.DetectedVulnerability, _ int) bool {
		found, ok := lo.Find(v.advisory.Vulnerabilities, func(item *csaf.Vulnerability) bool {
			return string(*item.CVE) == vuln.VulnerabilityID
		})
		if !ok {
			return true
		}

		return v.affected(found, vuln.PkgIdentifier.PURL)
	})
}

func (v *CSAF) affected(vuln *csaf.Vulnerability, pkgURL *packageurl.PackageURL) bool {
	if pkgURL == nil || vuln.ProductStatus == nil {
		return true
	}

	matchProduct := func(purls []*purl.PackageURL, pkgURL *packageurl.PackageURL) bool {
		for _, p := range purls {
			if p.Match(pkgURL) {
				return true
			}
		}
		return false
	}

	for _, product := range lo.FromPtr(vuln.ProductStatus.KnownNotAffected) {
		if matchProduct(v.getProductPurls(lo.FromPtr(product)), pkgURL) {
			v.logger.Infow("Filtered out the detected vulnerability",
				zap.String("vulnerability-id", string(*vuln.CVE)),
				zap.String("status", string(StatusNotAffected)))
			return false
		}
		for relationship, purls := range v.inspectProductRelationships(lo.FromPtr(product)) {
			if matchProduct(purls, pkgURL) {
				v.logger.Warnw("Filtered out the detected vulnerability",
					zap.String("vulnerability-id", string(*vuln.CVE)),
					zap.String("status", string(StatusNotAffected)),
					zap.String("relationship", string(relationship)))
				return false
			}
		}
	}

	for _, product := range lo.FromPtr(vuln.ProductStatus.Fixed) {
		if matchProduct(v.getProductPurls(lo.FromPtr(product)), pkgURL) {
			v.logger.Infow("Filtered out the detected vulnerability",
				zap.String("vulnerability-id", string(*vuln.CVE)),
				zap.String("status", string(StatusFixed)))
			return false
		}
		for relationship, purls := range v.inspectProductRelationships(lo.FromPtr(product)) {
			if matchProduct(purls, pkgURL) {
				v.logger.Warnw("Filtered out the detected vulnerability",
					zap.String("vulnerability-id", string(*vuln.CVE)),
					zap.String("status", string(StatusFixed)),
					zap.String("relationship", string(relationship)))
				return false
			}
		}
	}

	return true
}

// getProductPurls returns a slice of PackageURLs associated to a given product
func (v *CSAF) getProductPurls(product csaf.ProductID) []*purl.PackageURL {
	return purlsFromProductIdentificationHelpers(v.advisory.ProductTree.CollectProductIdentificationHelpers(product))
}

// inspectProductRelationships returns a map of PackageURLs associated to each relationship category
// iterating over relationships looking for sub-products that might be part of the original product
func (v *CSAF) inspectProductRelationships(product csaf.ProductID) map[csaf.RelationshipCategory][]*purl.PackageURL {
	subProductsMap := make(map[csaf.RelationshipCategory]csaf.Products)
	if v.advisory.ProductTree.RelationShips == nil {
		return nil
	}

	for _, rel := range lo.FromPtr(v.advisory.ProductTree.RelationShips) {
		if rel != nil {
			relationship := lo.FromPtr(rel.Category)
			switch relationship {
			case csaf.CSAFRelationshipCategoryDefaultComponentOf,
				csaf.CSAFRelationshipCategoryInstalledOn,
				csaf.CSAFRelationshipCategoryInstalledWith:
				if fpn := rel.FullProductName; fpn != nil && lo.FromPtr(fpn.ProductID) == product {
					subProductsMap[relationship] = append(subProductsMap[relationship], rel.ProductReference)
				}
			}
		}
	}

	purlsMap := make(map[csaf.RelationshipCategory][]*purl.PackageURL)
	for relationship, subProducts := range subProductsMap {
		var helpers []*csaf.ProductIdentificationHelper
		for _, subProductRef := range subProducts {
			helpers = append(helpers, v.advisory.ProductTree.CollectProductIdentificationHelpers(lo.FromPtr(subProductRef))...)
		}
		purlsMap[relationship] = purlsFromProductIdentificationHelpers(helpers)
	}

	return purlsMap
}

// purlsFromProductIdentificationHelpers returns a slice of PackageURLs given a slice of ProductIdentificationHelpers.
func purlsFromProductIdentificationHelpers(helpers []*csaf.ProductIdentificationHelper) []*purl.PackageURL {
	return lo.FilterMap(helpers, func(helper *csaf.ProductIdentificationHelper, _ int) (*purl.PackageURL, bool) {
		if helper == nil || helper.PURL == nil {
			return nil, false
		}
		p, err := purl.FromString(string(*helper.PURL))
		if err != nil {
			log.Logger.Errorw("Invalid PURL", zap.String("purl", string(*helper.PURL)), zap.Error(err))
			return nil, false
		}
		return p, true
	})
}
