package notification

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintNotices(t *testing.T) {
	tests := []struct {
		name             string
		options          []Option
		latestVersion    string
		announcements    []announcement
		responseExpected bool
		expectedOutput   string
	}{
		{
			name:             "New version with no announcements",
			options:          []Option{WithCurrentVersion("0.58.0")},
			latestVersion:    "0.60.0",
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name: "new version available but --quiet mode enabled",
			options: []Option{
				WithCurrentVersion("0.58.0"),
				WithQuietMode(true),
			},
			latestVersion:    "0.60.0",
			responseExpected: false,
			expectedOutput:   "",
		},
		{
			name: "new version available but --skip-update-check mode enabled",
			options: []Option{
				WithCurrentVersion("0.58.0"),
				WithSkipUpdateCheck(true),
			},
			latestVersion:    "0.60.0",
			responseExpected: false,
			expectedOutput:   "",
		},
		{
			name:          "New version with announcements",
			options:       []Option{WithCurrentVersion("0.58.0")},
			latestVersion: "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:          "No new version with announcements",
			options:       []Option{WithCurrentVersion("0.60.0")},
			latestVersion: "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := newUpdatesServer(t, tt.latestVersion, tt.announcements)
			server := httptest.NewServer(http.HandlerFunc(updates.handler))
			defer server.Close()
			tt.options = append(tt.options, WithUpdatesApi(server.URL))
			v := NewVersionChecker(tt.options...)

			v.RunUpdateCheck(t.Context(), nil)
			require.Eventually(t, func() bool { return v.done == true }, time.Second*5, 500)
			require.Eventually(t, func() bool { return v.responseReceived == tt.responseExpected }, time.Second*5, 500)

			sb := bytes.NewBufferString("")
			v.PrintNotices(sb)
			assert.Equal(t, tt.expectedOutput, sb.String())

			// check metrics are sent
			require.NotNil(t, updates.lastRequest)
			require.NotEmpty(t, updates.lastRequest.Header.Get("Trivy-Identifier"))
		})
	}
}

func TestCheckForNotices(t *testing.T) {
	tests := []struct {
		name                  string
		options               []Option
		expectedVersion       string
		expectedAnnouncements []announcement
		expectNoMetrics       bool
	}{
		{
			name: "new version with no announcements",
			options: []Option{
				WithCurrentVersion("0.58.0"),
			},
			expectedVersion: "0.60.0",
		},
		{
			name: "new version with disabled metrics",
			options: []Option{
				WithCurrentVersion("0.58.0"),
				WithTelemetryDisabled(true),
			},
			expectedVersion: "0.60.0",
			expectNoMetrics: true,
		},
		{
			name: "new version and a new announcement",
			options: []Option{
				WithCurrentVersion("0.58.0"),
			},
			expectedVersion: "0.60.0",
			expectedAnnouncements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := newUpdatesServer(t, tt.expectedVersion, tt.expectedAnnouncements)
			server := httptest.NewServer(http.HandlerFunc(updates.handler))
			defer server.Close()

			tt.options = append(tt.options, WithUpdatesApi(server.URL))
			v := NewVersionChecker(tt.options...)

			v.RunUpdateCheck(t.Context(), nil)
			require.Eventually(t, func() bool { return v.done == true }, time.Second*5, 500)
			require.Eventually(t, func() bool { return v.responseReceived == true }, time.Second*5, 500)
			assert.Equal(t, tt.expectedVersion, v.LatestVersion())
			assert.ElementsMatch(t, tt.expectedAnnouncements, v.Announcements())

			if tt.expectNoMetrics {
				assert.True(t, v.telemetryDisabled)
				require.NotNil(t, updates.lastRequest)
				assert.Empty(t, updates.lastRequest.Header.Get("Trivy-Identifier"))
			} else {
				assert.False(t, v.telemetryDisabled)
				require.NotNil(t, updates.lastRequest)
				assert.NotEmpty(t, updates.lastRequest.Header.Get("Trivy-Identifier"))
			}

		})
	}
}

type updatesServer struct {
	t                     *testing.T
	lastRequest           *http.Request
	expectedVersion       string
	expectedAnnouncements []announcement
}

func newUpdatesServer(t *testing.T, expectedVersion string, expectedAnnouncements []announcement) *updatesServer {
	return &updatesServer{
		t:                     t,
		expectedVersion:       expectedVersion,
		expectedAnnouncements: expectedAnnouncements,
	}
}

func (u *updatesServer) handler(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "trivy") {
		w.WriteHeader(http.StatusForbidden)
	}

	u.lastRequest = r

	response := updateResponse{
		Trivy: versionInfo{
			LatestVersion: u.expectedVersion,
			LatestDate:    time.Now(),
		},
		Announcements: u.expectedAnnouncements,
	}

	out, err := json.Marshal(response)
	if err != nil {
		u.t.Fail()
	}
	w.Write(out)
}
