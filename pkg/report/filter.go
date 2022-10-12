package report

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

func Filter(ctx context.Context, report types.Report,
	severities []dbTypes.Severity, ignoreUnfixed bool,
	includeNonFailures bool, ignoreFile string, policyFile string,
	ignoredLicenses []string) (types.Report, error) {
	results := report.Results

	// Filter results
	for i := range results {
		err := result.Filter(ctx, &results[i], severities, ignoreUnfixed,
			includeNonFailures, ignoreFile, policyFile, ignoredLicenses)
		if err != nil {
			return types.Report{}, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
	}
	return report, nil
}
