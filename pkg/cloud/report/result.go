package report

import (
	"fmt"
	"io"

	"github.com/aquasecurity/tml"

	renderer "github.com/aquasecurity/trivy/pkg/report/table"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func writeResultsForARN(report *Report, results types.Results, output io.Writer, service, arn string, severities []dbTypes.Severity) error {

	// render scan title
	_ = tml.Fprintf(output, "\n<bold>Results for '%s' (%s Account %s)</bold>\n\n", arn, report.Provider, report.AccountID)

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

	return nil
}
