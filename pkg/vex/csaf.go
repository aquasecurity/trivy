package vex

import (
	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
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

func (v *CSAF) affected(vuln *csaf.Vulnerability, purl *ftypes.PackageURL) bool {
	if purl == nil || vuln.ProductStatus == nil {
		return true
	}

	var status Status
	switch {
	case v.affectedByStatus(purl, vuln.ProductStatus.KnownNotAffected):
		status = StatusNotAffected
	case v.affectedByStatus(purl, vuln.ProductStatus.Fixed):
		status = StatusFixed
	}

	if status != "" {
		v.logger.Infow("Filtered out the detected vulnerability",
			zap.String("vulnerability-id", string(*vuln.CVE)),
			zap.String("status", string(status)))
		return false
	}

	return true
}

// affectedByStatus returns true if a package (identified by a given PackageURL) belongs to certain status
// (e.g. KnownNotAffected, Fixed, etc.) which products are provided.
func (v *CSAF) affectedByStatus(purl *ftypes.PackageURL, statusProducts *csaf.Products) bool {
	for _, product := range lo.FromPtr(statusProducts) {
		helpers := v.collectProductIdentificationHelpers(lo.FromPtr(product))
		purls := lo.FilterMap(helpers, func(helper *csaf.ProductIdentificationHelper, _ int) (string, bool) {
			if helper == nil || helper.PURL == nil {
				return "", false
			}
			return string(*helper.PURL), true
		})
		if slices.Contains(purls, purl.String()) {
			return true
		}
	}

	return false
}

// collectProductIdentificationHelpers collects ProductIdentificationHelpers from the given CSAF product.
func (v *CSAF) collectProductIdentificationHelpers(product csaf.ProductID) []*csaf.ProductIdentificationHelper {
	helpers := v.advisory.ProductTree.CollectProductIdentificationHelpers(product)
	// Iterate over relationships looking for sub-products that might be part of the original product.
	var subProducts csaf.Products
	if rels := v.advisory.ProductTree.RelationShips; rels != nil {
		for _, rel := range lo.FromPtr(rels) {
			if rel != nil {
				switch lo.FromPtr(rel.Category) {
				case csaf.CSAFRelationshipCategoryDefaultComponentOf,
					csaf.CSAFRelationshipCategoryInstalledOn,
					csaf.CSAFRelationshipCategoryInstalledWith:
					if fpn := rel.FullProductName; fpn != nil && fpn.ProductID != nil &&
						lo.FromPtr(fpn.ProductID) == product {
						subProducts = append(subProducts, rel.ProductReference)
					}
				}
			}
		}
	}
	for _, subProduct := range subProducts {
		helpers = append(helpers, v.advisory.ProductTree.CollectProductIdentificationHelpers(lo.FromPtr(subProduct))...)
	}

	return helpers
}
