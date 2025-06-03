//go:build !integration

package report

import (
	"context"
	"time"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/types"
)

// getSarifTiming returns timing information for SARIF reports in production
func getSarifTiming(ctx context.Context, report types.Report) (*time.Time, *time.Time) {
	var scanStartTime, scanEndTime *time.Time

	// Use report.CreatedAt as scan start time if available
	if !report.CreatedAt.IsZero() {
		scanStartTime = &report.CreatedAt
	}
	
	// Use current time as scan end time
	currentTime := clock.Now(ctx)
	scanEndTime = &currentTime

	return scanStartTime, scanEndTime
}