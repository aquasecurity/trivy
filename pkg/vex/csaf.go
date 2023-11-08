package vex

import (
	csaf "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

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

		return v.affected(found, vuln.PkgRef)
	})
}

func (v *CSAF) affected(vuln *csaf.Vulnerability, pkgRef string) bool {
	if vuln.ProductStatus != nil {
		if vuln.ProductStatus.KnownNotAffected != nil {
			notAffectedPURLs := findProductsPURLs(v.advisory, *vuln.ProductStatus.KnownNotAffected)
			if slices.Contains(notAffectedPURLs, pkgRef) {
				v.logger.Infow(
					"Filtered out the detected vulnerability",
					zap.String("vulnerability-id", string(*vuln.CVE)),
					zap.String("status", string(StatusNotAffected)),
				)
				return false
			}
		}
		if vuln.ProductStatus.Fixed != nil {
			fixedPURLS := findProductsPURLs(v.advisory, *vuln.ProductStatus.Fixed)
			if slices.Contains(fixedPURLS, pkgRef) {
				v.logger.Infow(
					"Filtered out the detected vulnerability",
					zap.String("vulnerability-id", string(*vuln.CVE)),
					zap.String("status", string(StatusFixed)),
				)
				return false
			}
		}
	}

	return true
}
