package notification

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintNotices(t *testing.T) {
	tests := []struct {
		name             string
		skipVersionCheck bool
		quiet            bool
		disableTelemetry bool

		currentVersion   string
		latestVersion    string
		announcements    []announcement
		responseExpected bool
		expectedOutput   string
	}{
		{
			name:             "New version with no announcements",
			currentVersion:   "0.58.0",
			latestVersion:    "0.60.0",
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:             "New version available but includes a prefixed version number",
			currentVersion:   "0.58.0",
			latestVersion:    "v0.60.0",
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:             "new version available but --quiet mode enabled",
			quiet:            true,
			currentVersion:   "0.58.0",
			latestVersion:    "0.60.0",
			responseExpected: false,
			expectedOutput:   "",
		},
		{
			name:             "new version available but --skip-version-check mode enabled",
			skipVersionCheck: true,
			currentVersion:   "0.58.0",
			latestVersion:    "0.60.0",
			responseExpected: false,
			expectedOutput:   "",
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
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n  - Version 0.60.0 of Trivy is now available, current version is 0.58.0\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
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
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:           "No new version with announcements and zero time",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Time{},
					ToDate:       time.Time{},
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:           "No new version with announcement that fails announcement version constraints",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					FromVersion:  "0.61.0",
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "",
		},
		{
			name:           "No new version with announcement where current version is greater than to_version",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					ToVersion:    "0.59.0",
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "",
		},
		{
			name:           "No new version with announcement that satisfies version constraint but outside date range",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2024, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
					FromVersion:  "0.60.0",
					Announcement: "There are some amazing things happening right now!",
				},
			},
			responseExpected: true,
			expectedOutput:   "",
		},
		{
			name:           "No new version with multiple announcements, one of which is valid",
			currentVersion: "0.60.0",
			latestVersion:  "0.60.0",
			announcements: []announcement{
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					Announcement: "There are some amazing things happening right now!",
				},
				{
					FromDate:     time.Date(2025, 2, 2, 12, 0, 0, 0, time.UTC),
					ToDate:       time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
					FromVersion:  "0.61.0",
					Announcement: "This announcement should not be displayed",
				},
			},
			responseExpected: true,
			expectedOutput:   "\n📣 \x1b[34mNotices:\x1b[0m\n  - There are some amazing things happening right now!\n\nTo suppress version checks, run Trivy scans with the --skip-version-check flag\n\n",
		},
		{
			name:             "No new version with no announcements and quiet mode",
			quiet:            true,
			currentVersion:   "0.60.0",
			latestVersion:    "0.60.0",
			announcements:    []announcement{},
			responseExpected: false,
			expectedOutput:   "",
		},
		{
			name:             "No new version with no announcements",
			currentVersion:   "0.60.0",
			latestVersion:    "0.60.0",
			announcements:    []announcement{},
			responseExpected: true,
			expectedOutput:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := newUpdatesServer(t, tt.latestVersion, tt.announcements)
			server := httptest.NewServer(http.HandlerFunc(updates.handler))

			cliOpts := &flag.Options{
				GlobalOptions: flag.GlobalOptions{
					Quiet: tt.quiet,
				},
				ScanOptions: flag.ScanOptions{
					SkipVersionCheck: tt.skipVersionCheck,
					DisableTelemetry: tt.disableTelemetry,
				},
			}

			v := NewVersionChecker("testCommand", cliOpts)
			v.updatesApi = server.URL
			v.currentVersion = tt.currentVersion

			v.RunUpdateCheck(t.Context())
			require.Eventually(t, func() bool { return v.done }, time.Second*5, 500)
			require.Eventually(t, func() bool { return v.responseReceived == tt.responseExpected }, time.Second*5, 500)

			sb := bytes.NewBufferString("")
			v.PrintNotices(t.Context(), sb)
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
		skipVersionCheck      bool
		disableTelemetry      bool
		quiet                 bool
		currentVersion        string
		expectedVersion       string
		expectedAnnouncements []announcement
		expectNoMetrics       bool
	}{
		{
			name:            "new version with no announcements",
			currentVersion:  "0.58.0",
			expectedVersion: "0.60.0",
		},
		{
			name:             "new version with disabled metrics",
			disableTelemetry: true,
			currentVersion:   "0.58.0",
			expectedVersion:  "0.60.0",
			expectNoMetrics:  true,
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
			updates := newUpdatesServer(t, tt.expectedVersion, tt.expectedAnnouncements)
			server := httptest.NewServer(http.HandlerFunc(updates.handler))
			defer server.Close()

			cliOpts := &flag.Options{
				GlobalOptions: flag.GlobalOptions{
					Quiet: tt.quiet,
				},
				ScanOptions: flag.ScanOptions{
					SkipVersionCheck: tt.skipVersionCheck,
					DisableTelemetry: tt.disableTelemetry,
				},
			}

			v := NewVersionChecker("testCommand", cliOpts)
			v.updatesApi = server.URL

			v.RunUpdateCheck(t.Context())
			require.Eventually(t, func() bool { return v.done }, time.Second*5, 500)
			require.Eventually(t, func() bool { return v.responseReceived }, time.Second*5, 500)
			latestVersion, err := v.LatestVersion()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedVersion, latestVersion.String())
			assert.ElementsMatch(t, tt.expectedAnnouncements, v.Announcements())

			if tt.expectNoMetrics {
				assert.True(t, v.disableTelemetry)
				require.NotNil(t, updates.lastRequest)
				assert.Empty(t, updates.lastRequest.Header.Get("Trivy-Identifier"))
			} else {
				assert.False(t, v.disableTelemetry)
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
			LatestDate:    flexibleTime{Time: time.Now()},
		},
		Announcements: u.expectedAnnouncements,
	}

	out, err := json.Marshal(response)
	if err != nil {
		u.t.Fail()
	}
	w.Write(out)
}

func TestFlexibleDate(t *testing.T) {
	tests := []struct {
		name     string
		dateStr  string
		expected time.Time
	}{
		{
			name:     "RFC3339 date format",
			dateStr:  `"2023-10-01T12:00:00Z"`,
			expected: time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "RFC1123 date format",
			dateStr:  `"Sun, 01 Oct 2023 12:00:00 GMT"`,
			expected: time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "RFC3339 date only format",
			dateStr:  `"2023-10-01"`,
			expected: time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ft flexibleTime
			err := json.Unmarshal([]byte(tt.dateStr), &ft)
			require.NoError(t, err)
			assert.Equal(t, tt.expected.Unix(), ft.Unix())
		})
	}
}

func TestCheckCommandHeaders(t *testing.T) {
	tests := []struct {
		name                      string
		command                   string
		commandArgs               []string
		env                       map[string]string
		ignoreParseError          bool
		expectedCommandHeader     string
		expectedCommandArgsHeader string
	}{
		{
			name:                  "image command with no flags",
			command:               "image",
			commandArgs:           []string{"nginx"},
			expectedCommandHeader: "image",
		},
		{
			name:                      "image command with flags",
			command:                   "image",
			commandArgs:               []string{"--severity", "CRITICAL", "--scanners", "vuln,misconfig", "--pkg-types", "library", "nginx", "--include-dev-deps"},
			expectedCommandHeader:     "image",
			expectedCommandArgsHeader: "--include-dev-deps=true --pkg-types=library --severity=CRITICAL --scanners=vuln,misconfig",
		},
		{
			name:                      "image command with multiple flags",
			command:                   "image",
			commandArgs:               []string{"--severity", "MEDIUM", "-s", "CRITICAL", "--scanners", "misconfig", "nginx"},
			expectedCommandHeader:     "image",
			expectedCommandArgsHeader: "--severity=MEDIUM,CRITICAL --scanners=misconfig",
		},
		{
			name:                      "filesystem command with flags",
			command:                   "fs",
			commandArgs:               []string{"--severity=HIGH", "--vex", "repo", "--vuln-severity-source", "nvd,debian", "../trivy-ci-test"},
			expectedCommandHeader:     "fs",
			expectedCommandArgsHeader: "--severity=HIGH --vex=****** --vuln-severity-source=nvd,debian",
		},
		{
			name:                      "filesystem command with flags including an invalid flag",
			command:                   "fs",
			commandArgs:               []string{"--severity=HIGH", "--vex", "repo", "--vuln-severity-source", "nvd,debian", "--invalid-flag", "../trivy-ci-test"},
			ignoreParseError:          true,
			expectedCommandHeader:     "fs",
			expectedCommandArgsHeader: "--severity=HIGH --vex=****** --vuln-severity-source=nvd,debian",
		},
		{
			name:        "filesystem with environment variables",
			command:     "fs",
			commandArgs: []string{"--severity", "HIGH", "--vex", "repo", "/home/user/code"},
			env: map[string]string{
				"TRIVY_SCANNERS": "secret,misconfig",
			},
			expectedCommandHeader:     "fs",
			expectedCommandArgsHeader: "--severity=HIGH --scanners=secret,misconfig --vex=******",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := newUpdatesServer(t, "0.60.0", nil)
			server := httptest.NewServer(http.HandlerFunc(updates.handler))
			defer server.Close()

			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			// clean up the env
			defer func() {
				server.Close()
				for key := range tt.env {
					t.Setenv(key, "")
				}
			}()

			opts := getOptionsForArgs(t, tt.commandArgs, tt.ignoreParseError)

			v := NewVersionChecker(tt.command, opts)
			v.updatesApi = server.URL
			v.RunUpdateCheck(t.Context())

			require.Eventually(t, func() bool { return v.done }, time.Second*5, 500)
			require.NotNil(t, updates.lastRequest)
			assert.Equal(t, tt.expectedCommandHeader, updates.lastRequest.Header.Get("Trivy-Command"))
			assert.Equal(t, tt.expectedCommandArgsHeader, updates.lastRequest.Header.Get("Trivy-Flags"))
		})
	}
}
