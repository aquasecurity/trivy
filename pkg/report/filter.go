package report

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Filter(ctx context.Context, report types.Report, filters types.ResultFilters) (types.Report, error) {
	results := report.Results

	// Filter results
	for i := range results {
		err := result.Filter(ctx, &results[i], filters)
		if err != nil {
			return types.Report{}, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
	}
	return report, nil
}
