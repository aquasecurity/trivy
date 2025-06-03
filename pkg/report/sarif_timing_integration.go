//go:build integration

package report

import (
	"context"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
)

// getSarifTiming returns fixed timing information for SARIF reports in integration tests
func getSarifTiming(ctx context.Context, report types.Report) (*time.Time, *time.Time) {
	// Use fixed timestamps for integration tests to ensure reproducible output
	fixedStart := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	fixedEnd := time.Date(2023, 1, 1, 12, 0, 30, 0, time.UTC)

	return &fixedStart, &fixedEnd
}
