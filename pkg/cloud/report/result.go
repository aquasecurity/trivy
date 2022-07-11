package report

import (
	"fmt"

	renderer "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/term"
)

func writeResultsForARN(report *Report, option Option) error {

	width, _, err := term.GetSize(0)
	if err != nil {
		width = 80
	}
	_ = width

	w := option.Output

	// render scan title
	_, _ = fmt.Fprintf(w, "\n\x1b[1mResults for '%s' (AWS Account %s)\x1b[0m\n\n", option.ARN, report.AccountID)

	for _, result := range report.Results {
		var filtered []types.DetectedMisconfiguration
		for _, misconfiguration := range result.Misconfigurations {
			if option.ARN != "" && misconfiguration.CauseMetadata.Resource != option.ARN {
				continue
			}
			if option.Service != "" && misconfiguration.CauseMetadata.Service != option.Service {
				continue
			}
			filtered = append(filtered, misconfiguration)
		}
		if len(filtered) > 0 {
			_, _ = fmt.Fprint(w, renderer.NewMisconfigRenderer(result.Target, filtered, false, true).Render())
		}
	}

	// render cache info
	if option.FromCache {
		_, _ = fmt.Fprintf(w, "\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}
