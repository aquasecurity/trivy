package vex

import (
	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"go.uber.org/zap"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
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

func (v *CSAF) Filter(result *types.Result, _ *core.BOM) {
	result.Vulnerabilities = lo.Filter(result.Vulnerabilities, func(vuln types.DetectedVulnerability, _ int) bool {
		found, ok := lo.Find(v.advisory.Vulnerabilities, func(item *csaf.Vulnerability) bool {
			return string(*item.CVE) == vuln.VulnerabilityID
		})
		if !ok {
			return true
		}

		if status := v.match(found, vuln.PkgIdentifier.PURL); status != "" {
			result.ModifiedFindings = append(result.ModifiedFindings,
				types.NewModifiedFinding(vuln, status, statement(found), "CSAF VEX"))
			return false
		}
		return true
	})
}

func (v *CSAF) match(vuln *csaf.Vulnerability, pkgURL *packageurl.PackageURL) types.FindingStatus {
	if pkgURL == nil || vuln.ProductStatus == nil {
		return ""
	}

	matchProduct := func(purls []*purl.PackageURL, pkgURL *packageurl.PackageURL) bool {
		for _, p := range purls {
			if p.Match(pkgURL) {
				return true
			}
		}
		return false
	}

	productStatusMap := map[types.FindingStatus]csaf.Products{
		types.FindingStatusNotAffected: lo.FromPtr(vuln.ProductStatus.KnownNotAffected),
		types.FindingStatusFixed:       lo.FromPtr(vuln.ProductStatus.Fixed),
	}
	for status, productRange := range productStatusMap {
		for _, product := range productRange {
			if matchProduct(v.getProductPurls(lo.FromPtr(product)), pkgURL) {
				v.logger.Infow("Filtered out the detected vulnerability",
					zap.String("vulnerability-id", string(*vuln.CVE)),
					zap.String("status", string(status)))
				return status
			}
			for relationship, purls := range v.inspectProductRelationships(lo.FromPtr(product)) {
				if matchProduct(purls, pkgURL) {
					v.logger.Warnw("Filtered out the detected vulnerability",
						zap.String("vulnerability-id", string(*vuln.CVE)),
						zap.String("status", string(status)),
						zap.String("relationship", string(relationship)))
					return status
				}
			}
		}
	}

	return ""
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

func statement(vuln *csaf.Vulnerability) string {
	threat, ok := lo.Find(vuln.Threats, func(threat *csaf.Threat) bool {
		return lo.FromPtr(threat.Category) == csaf.CSAFThreatCategoryImpact
	})
	if !ok {
		return ""
	}
	return lo.FromPtr(threat.Details)
}
