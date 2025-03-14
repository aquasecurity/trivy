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
		name           string
		currentVersion string
		latestVersion  string
		announcements  []announcement
		expectedOutput string
	}{
		{
			name:           "New version with no announcements",
			currentVersion: "0.58.0",
			latestVersion:  "0.60.0",
			expectedOutput: "\n📣 \x1b[34mNotices:\x1b[0m\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --no-notices flag\n\n",
		},
		{
			name:           "New version with announcements",
			currentVersion: "0.58.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
			},
			expectedOutput: "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --no-notices flag\n\n",
		},
		{
			name:           "No new version with announcements",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
			},
			expectedOutput: "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n\nTo suppress version checks, run Trivy scans with the --no-notices flag\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// reset the updated flag
			responseRecieved.Store(false)
			server := httptest.NewServer(http.HandlerFunc(createHandler(t, tt.latestVersion, tt.announcements)))
			defer server.Close()
			updatesApi = server.URL

			CheckForNotices(t.Context(), tt.currentVersion, nil)
			require.Eventually(t, responseRecieved.Load, time.Second*5, 500)

			sb := bytes.NewBufferString("")
			PrintNotices(sb)
			assert.Equal(t, tt.expectedOutput, sb.String())
		})
	}
}

func TestCheckForNotices(t *testing.T) {
	tests := []struct {
		name                  string
		currentVersion        string
		expectedVersion       string
		expectedAnnouncements []announcement
	}{
		{
			name:            "new version with no announcements",
			currentVersion:  "0.58.0",
			expectedVersion: "0.60.0",
		},
		{
			name:            "new version and a new announcement",
			currentVersion:  "0.58.0",
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
			// reset the updated flag
			responseRecieved.Store(false)

			server := httptest.NewServer(http.HandlerFunc(createHandler(t, tt.expectedVersion, tt.expectedAnnouncements)))
			defer server.Close()
			updatesApi = server.URL

			CheckForNotices(t.Context(), tt.currentVersion, nil)
			require.Eventually(t, responseRecieved.Load, time.Second*2, 500)
			assert.Equal(t, tt.expectedVersion, latestVersion.Trivy.LatestVersion)
			assert.ElementsMatch(t, tt.expectedAnnouncements, latestVersion.Announcements)

		})
	}
}

func createHandler(t *testing.T, expectedVersion string, announcements []announcement) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "trivy") {
			w.WriteHeader(http.StatusForbidden)
		}

		response := updateResponse{
			Trivy: versionInfo{
				LatestVersion: expectedVersion,
				LatestDate:    time.Now(),
			},
			Announcements: announcements,
		}

		out, err := json.Marshal(response)
		if err != nil {
			t.Fail()
		}
		w.Write(out)
	}
}
