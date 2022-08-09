package report

import (
	"fmt"
	"io"

	renderer "github.com/aquasecurity/trivy/pkg/report/table"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func writeResultsForARN(report *Report, results types.Results, output io.Writer, fromCache bool, service, arn string, severities []dbTypes.Severity) error {

	// render scan title
	_, _ = fmt.Fprintf(output, "\n\x1b[1mResults for '%s' (%s Account %s)\x1b[0m\n\n", arn, report.Provider, report.AccountID)

	for _, result := range results {
		var filtered []types.DetectedMisconfiguration
		for _, misconfiguration := range result.Misconfigurations {
			if arn != "" && misconfiguration.CauseMetadata.Resource != arn {
				continue
			}
			if service != "" && misconfiguration.CauseMetadata.Service != service {
				continue
			}
			filtered = append(filtered, misconfiguration)
		}
		if len(filtered) > 0 {
			_, _ = fmt.Fprint(output, renderer.NewMisconfigRenderer(result, severities, false, false, true).Render())
		}
	}

	// render cache info
	if fromCache {
		_, _ = fmt.Fprintf(output, "\x1b[34mThis scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.\x1b[0m\n")
	}

	return nil
}
