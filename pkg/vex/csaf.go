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

	var status Status
	switch {
	case v.matchPURL(vuln.ProductStatus.KnownNotAffected, pkgURL):
		status = StatusNotAffected
	case v.matchPURL(vuln.ProductStatus.Fixed, pkgURL):
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
func (v *CSAF) matchPURL(products *csaf.Products, pkgURL *packageurl.PackageURL) bool {
	for _, product := range lo.FromPtr(products) {
		helpers := v.advisory.ProductTree.CollectProductIdentificationHelpers(lo.FromPtr(product))
		purls := lo.FilterMap(helpers, func(helper *csaf.ProductIdentificationHelper, _ int) (*purl.PackageURL, bool) {
			if helper == nil || helper.PURL == nil {
				return nil, false
			}
			p, err := purl.FromString(string(*helper.PURL))
			if err != nil {
				v.logger.Errorw("Invalid PURL", zap.String("purl", string(*helper.PURL)), zap.Error(err))
				return nil, false
			}
			return p, true
		})
		for _, p := range purls {
			if p.Match(pkgURL) {
				return true
			}
		}
	}

	return false
}
