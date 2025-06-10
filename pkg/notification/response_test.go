package notification

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-version/pkg/semver"
)

func TestAnnouncementShouldDisplay(t *testing.T) {
	tests := []struct {
		name           string
		announcement   announcement
		now            time.Time
		currentVersion string
		expected       bool
	}{
		{
			name: "Announcement with valid from_date and current date before it",
			announcement: announcement{
				FromDate:     ptrTime(time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)),
				Announcement: "Upcoming feature",
			},
			now:            time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC),
			currentVersion: "1.0.0",
			expected:       false,
		},
		{
			name: "Announcement with valid to_date and current date after it",
			announcement: announcement{
				ToDate:       ptrTime(time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)),
				Announcement: "Past feature",
			},
			now:            time.Date(2023, 10, 2, 0, 0, 0, 0, time.UTC),
			currentVersion: "1.0.0",
			expected:       false,
		},
		{
			name: "Announcement with valid from_date and current date after it and before to_date",
			announcement: announcement{
				FromDate:     ptrTime(time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)),
				ToDate:       ptrTime(time.Date(2023, 10, 31, 0, 0, 0, 0, time.UTC)),
				Announcement: "Ongoing feature",
			},
			now:            time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
			currentVersion: "1.0.0",
			expected:       true,
		},
		{
			name: "Announcement with valid from_version and current version greater than it",
			announcement: announcement{
				FromVersion:  ptrString("1.1.0"),
				Announcement: "New feature",
			},
			now:            time.Now(),
			currentVersion: "1.2.0",
			expected:       true,
		},
		{
			name: "Announcement with valid from_version and current version equal to it",
			announcement: announcement{
				FromVersion:  ptrString("1.0.0"),
				Announcement: "New feature",
			},
			now:            time.Now(),
			currentVersion: "1.0.0",
			expected:       true,
		},
		{
			name: "Announcement with valid to_version and current version less than it",
			announcement: announcement{
				ToVersion:    ptrString("1.2.0"),
				Announcement: "Upcoming feature",
			},
			now:            time.Now(),
			currentVersion: "1.0.0",
			expected:       true,
		},
		{
			name: "Announcement with valid to_version and current version equal to it",
			announcement: announcement{
				ToVersion:    ptrString("1.0.0"),
				Announcement: "Upcoming feature",
			},
			now:            time.Now(),
			currentVersion: "1.0.0",
			expected:       false,
		},
		{
			name: "Announcement with valid from_version and valid to_version",
			announcement: announcement{
				FromVersion:  ptrString("1.0.0"),
				ToVersion:    ptrString("1.2.0"),
				Announcement: "Feature announcement",
			},
			now:            time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
			currentVersion: "1.1.0",
			expected:       true,
		},
		{
			name: "Announcement with no date or version constraints",
			announcement: announcement{
				Announcement: "General announcement",
			},
			now:            time.Now(),
			currentVersion: "1.0.0",
			expected:       true,
		},
		{
			name: "Announcement with all constraints but current version meets them",
			announcement: announcement{
				FromDate:     ptrTime(time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)),
				ToDate:       ptrTime(time.Date(2023, 10, 31, 0, 0, 0, 0, time.UTC)),
				FromVersion:  ptrString("1.0.0"),
				ToVersion:    ptrString("1.2.0"),
				Announcement: "Feature announcement",
			},
			now:            time.Date(2023, 10, 15, 0, 0, 0, 0, time.UTC),
			currentVersion: "1.1.0",
			expected:       true,
		},
		{
			name: "Announcement with version having 'v' prefix",
			announcement: announcement{
				FromVersion:  ptrString("v1.0.0"),
				Announcement: "Version prefix handling",
			},
			now:            time.Now(),
			currentVersion: "1.0.0",
			expected:       true,
		},
		{
			name: "Current version with 'v' prefix",
			announcement: announcement{
				FromVersion:  ptrString("1.0.0"),
				Announcement: "Version prefix handling",
			},
			now:            time.Now(),
			currentVersion: "v1.0.0",
			expected:       true,
		},
		{
			name: "Pre-release version comparison",
			announcement: announcement{
				FromVersion:  ptrString("1.0.0"),
				ToVersion:    ptrString("1.2.0"),
				Announcement: "Pre-release handling",
			},
			now:            time.Now(),
			currentVersion: "1.1.0-beta.1",
			expected:       true,
		},
		{
			name: "Build metadata in version",
			announcement: announcement{
				FromVersion:  ptrString("1.0.0"),
				Announcement: "Build metadata handling",
			},
			now:            time.Now(),
			currentVersion: "1.0.0+build.1",
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentVersion, err := semver.Parse(strings.TrimPrefix(tt.currentVersion, "v"))
			require.NoError(t, err)
			got := tt.announcement.shouldDisplay(tt.now, currentVersion)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func ptrString(s string) *string {
	return &s
}
