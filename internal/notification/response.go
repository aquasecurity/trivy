package notification

import (
	"context"
	"time"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/clock"
)

// flexibleTime is a custom time type that can handle
// different date formats in JSON. It implements the
// UnmarshalJSON method to parse the date string into a time.Time object.
type flexibleTime struct {
	time.Time
}

type versionInfo struct {
	LatestVersion string       `json:"latest_version"`
	LatestDate    flexibleTime `json:"latest_date"`
}

type announcement struct {
	FromDate     time.Time `json:"from_date"`
	ToDate       time.Time `json:"to_date"`
	FromVersion  string    `json:"from_version"`
	ToVersion    string    `json:"to_version"`
	Announcement string    `json:"announcement"`
}

type updateResponse struct {
	Trivy         versionInfo    `json:"trivy"`
	Announcements []announcement `json:"announcements"`
	Warnings      []string       `json:"warnings"`
}

// shouldDisplay checks if the announcement should be displayed
// based on the current time and version. If version and date constraints are provided
// they are checked against the current time and version.
func (a *announcement) shouldDisplay(ctx context.Context, currentVersion semver.Version) bool {
	if !a.FromDate.IsZero() && clock.Now(ctx).Before(a.FromDate) {
		return false
	}
	if !a.ToDate.IsZero() && clock.Now(ctx).After(a.ToDate) {
		return false
	}
	if a.FromVersion != "" {
		if fromVersion, err := semver.Parse(a.FromVersion); err == nil && currentVersion.LessThan(fromVersion) {
			return false
		}
	}
	if a.ToVersion != "" {
		if toVersion, err := semver.Parse(a.ToVersion); err == nil && currentVersion.GreaterThanOrEqual(toVersion) {
			return false
		}
	}
	return true
}
