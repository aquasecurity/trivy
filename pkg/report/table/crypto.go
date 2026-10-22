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

	severityCount := make(map[string]int)
	for _, f := range findings {
		severityCount[f.Severity]++
	}
	total, summaries := summarize(r.severities, severityCount)

	RenderTarget(r.w, result.Target+" (crypto)", r.isTerminal)
	r.printf("Total: %d (%s)\n\n", total, strings.Join(summaries, ", "))

	tw := newTableWriter(r.w, r.isTerminal)
	tw.SetColumnMaxWidth(40)
	tw.SetHeaders("Severity", "Rule ID", "Title", "Asset", "File", "Message")
	for _, f := range findings {
		severity := f.Severity
		if r.isTerminal {
			severity = ColorizeSeverity(f.Severity, f.Severity)
		}
		asset := assets[f.AssetID]
		tw.AddRow(severity, f.RuleID, f.Title, cryptoAssetLabel(asset), asset.FilePath, check.Message(f))
	}
	tw.Render()
}

func (r *cryptoRenderer) printf(format string, args ...any) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

// cryptoAssetLabel adds the container format to the asset name, so that copies of one key in
// different containers of a file give different rows.
func cryptoAssetLabel(a ftypes.CryptoAsset) string {
	if a.Format == "" {
		return a.Name
	}
	return fmt.Sprintf("%s (%s)", a.Name, a.Format)
}
