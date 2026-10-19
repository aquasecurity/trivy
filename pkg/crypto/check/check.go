// Package check evaluates the built-in checks of cryptographic assets.
package check

import (
	"cmp"
	"slices"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// rule is a built-in check for a cryptographic asset.
type rule struct {
	id       string
	title    string
	severity dbTypes.Severity
	kind     ftypes.CryptoKind
	// match reports whether the asset fails the rule and returns the evidence.
	// Unknown asset values never match.
	match func(asset ftypes.CryptoAsset, now time.Time) (types.CryptoEvidence, bool)
}

// match is a finding together with the asset it refers to.
type match struct {
	asset   ftypes.CryptoAsset
	finding types.CryptoFinding
}

// Evaluate returns the findings of the built-in checks for the given assets. The assets must
// already have their IDs and the security levels of algorithm assets.
func Evaluate(assets []ftypes.CryptoAsset, now time.Time) []types.CryptoFinding {
	var matches []match
	for _, asset := range assets {
		for _, r := range rules {
			if r.kind != asset.Kind {
				continue
			}
			evidence, matched := r.match(asset, now)
			if !matched {
				continue
			}
			matches = append(matches, match{
				asset: asset,
				finding: types.CryptoFinding{
					RuleID:   r.id,
					Title:    r.title,
					Severity: r.severity.String(),
					AssetID:  asset.AssetID,
					Evidence: evidence,
				},
			})
		}
	}
	slices.SortFunc(matches, compareMatches)
	var findings []types.CryptoFinding
	for _, m := range matches {
		findings = append(findings, m.finding)
	}
	return findings
}

func compareMatches(a, b match) int {
	return cmp.Or(
		cmp.Compare(a.asset.FilePath, b.asset.FilePath),
		cmp.Compare(a.finding.RuleID, b.finding.RuleID),
		a.asset.Descriptor().Compare(b.asset.Descriptor()),
		cmp.Compare(a.asset.Format, b.asset.Format),
		cmp.Compare(a.asset.Layer.DiffID, b.asset.Layer.DiffID),
	)
}
