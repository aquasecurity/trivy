package table

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/tml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/crypto/scanner"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
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
			cmp.Compare(cryptoAssetLabel(assetA), cryptoAssetLabel(assetB)),
			cmp.Compare(scanner.Message(a), scanner.Message(b)),
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
	for _, row := range groupCryptoFindings(findings, assets) {
		f := row.finding
		severity := f.Severity
		if r.isTerminal {
			severity = ColorizeSeverity(f.Severity, f.Severity)
		}
		label := cryptoAssetLabel(row.asset)
		if row.count > 1 {
			label = fmt.Sprintf("%s x%d", label, row.count)
		}
		message := tml.Sprintf("%s\n<blue>%s</blue>", scanner.Message(f), cryptoRuleURL(f.RuleID))
		tw.AddRow(severity, f.RuleID, label, row.asset.FilePath, message)
	}
	tw.Render()
}

// cryptoRow is a table row for findings that look the same.
type cryptoRow struct {
	finding types.CryptoFinding
	asset   ftypes.CryptoAsset
	count   int
}

// groupCryptoFindings joins neighboring findings of different assets that show the same values in the table.
// The findings must be sorted.
func groupCryptoFindings(findings []types.CryptoFinding, assets map[string]ftypes.CryptoAsset) []cryptoRow {
	var rows []cryptoRow
	for _, f := range findings {
		asset := assets[f.AssetID]
		if n := len(rows); n > 0 {
			prev := rows[n-1]
			if prev.finding.Severity == f.Severity && prev.finding.RuleID == f.RuleID &&
				prev.asset.FilePath == asset.FilePath && cryptoAssetLabel(prev.asset) == cryptoAssetLabel(asset) &&
				scanner.Message(prev.finding) == scanner.Message(f) {
				rows[n-1].count++
				continue
			}
		}
		rows = append(rows, cryptoRow{finding: f, asset: asset, count: 1})
	}
	return rows
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
