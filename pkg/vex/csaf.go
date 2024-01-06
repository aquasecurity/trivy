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
	case v.matchPURL(purl, vuln.ProductStatus.KnownNotAffected):
		status = StatusNotAffected
	case v.matchPURL(purl, vuln.ProductStatus.Fixed):
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

// matchPURL returns true if the given PackageURL is found in the ProductTree.
func (v *CSAF) matchPURL(purl *ftypes.PackageURL, products *csaf.Products) bool {
	for _, product := range lo.FromPtr(products) {
		helpers := v.advisory.ProductTree.CollectProductIdentificationHelpers(lo.FromPtr(product))
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
