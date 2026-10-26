package table

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/crypto/check"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
)

type cryptoRenderer struct {
	w          *bytes.Buffer
	isTerminal bool
	severities []dbTypes.Severity
}

func NewCryptoRenderer(buf *bytes.Buffer, isTerminal bool, severities []dbTypes.Severity) *cryptoRenderer {
	if !isTerminal {
		tml.DisableFormatting()
	}
	return &cryptoRenderer{
		w:          buf,
		isTerminal: isTerminal,
		severities: severities,
	}
}

func (r *cryptoRenderer) Render(result types.Result) {
	if len(result.CryptoFindings) == 0 {
		return
	}

	assets := make(map[string]ftypes.CryptoAsset, len(result.CryptoAssets))
	for _, asset := range result.CryptoAssets {
		assets[asset.AssetID] = asset
	}

	findings := slices.Clone(result.CryptoFindings)
	slices.SortStableFunc(findings, func(a, b types.CryptoFinding) int {
		assetA, assetB := assets[a.AssetID], assets[b.AssetID]
		return cmp.Or(
			dbTypes.CompareSeverityString(a.Severity, b.Severity),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(assetA.FilePath, assetB.FilePath),
			cmp.Compare(assetA.Name, assetB.Name),
		)
	})

	severityCount := lo.CountValuesBy(findings, func(f types.CryptoFinding) string {
		return f.Severity
	})
	total, summaries := summarize(r.severities, severityCount)

	RenderTarget(r.w, result.Target+" (crypto)", r.isTerminal)
	fmt.Fprintf(r.w, "Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	tw := newTableWriter(r.w, r.isTerminal)
	tw.SetHeaders("Severity", "Rule ID", "Asset", "File", "Message")
	for _, f := range findings {
		severity := f.Severity
		if r.isTerminal {
			severity = ColorizeSeverity(f.Severity, f.Severity)
		}
		asset := assets[f.AssetID]
		message := tml.Sprintf("%s\n<blue>%s</blue>", check.Message(f), cryptoRuleURL(f.RuleID))
		tw.AddRow(severity, f.RuleID, cryptoAssetLabel(asset), asset.FilePath, message)
	}
	tw.Render()
}

func cryptoRuleURL(ruleID string) string {
	return "https://avd.aquasec.com/crypto/" + strings.ToLower(ruleID) + "/"
}

func cryptoAssetLabel(a ftypes.CryptoAsset) string {
	name := a.Name
	switch a.Kind {
	case ftypes.CryptoKindCertificate:
		name += " certificate"
	case ftypes.CryptoKindAlgorithm:
		name += " algorithm"
	}
	if a.Format == "" {
		return name
	}
	// The format keeps the same key in different containers from being merged into one cell.
	return fmt.Sprintf("%s (%s)", name, a.Format)
}
