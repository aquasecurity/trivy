package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/app"
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
	Announcement string    `json:"announcement"`
}

type updateResponse struct {
	Trivy         versionInfo    `json:"trivy"`
	Announcements []announcement `json:"announcements"`
	Warnings      []string       `json:"warnings"`
}

type VersionChecker struct {
	updatesApi        string
	skipUpdateCheck   bool
	quiet             bool
	telemetryDisabled bool

	done             bool
	responseReceived bool
	currentVersion   string
	latestVersion    updateResponse
}

// NewVersionChecker creates a new VersionChecker with the default
// updates API URL. The URL can be overridden by passing an Option
// to the NewVersionChecker function.
func NewVersionChecker(opts ...Option) *VersionChecker {
	v := &VersionChecker{
		updatesApi:     "https://check.trivy.dev/updates",
		currentVersion: app.Version(),
	}

	for _, opt := range opts {
		opt(v)
	}
	return v
}

// RunUpdateCheck makes a best efforts request to determine the
// latest version and any announcements
// Logic:
// 1. if skipUpdateCheck is true AND telemetryDisabled are both true, skip the request
// 2. if skipUpdateCheck is true AND telemetryDisabled is false, run check with metric details but suppress output
// 3. if skipUpdateCheck is false AND telemetryDisabled is true, run update check but don't send any metric identifiers
func (v *VersionChecker) RunUpdateCheck(ctx context.Context, args []string) {
	logger := log.WithPrefix("notification")

	if v.skipUpdateCheck && v.telemetryDisabled {
		logger.Debug("Skipping update check and metric ping")
		return
	}

	go func() {
		logger.Debug("Running version check")
		args = getFlags(args)
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.updatesApi, http.NoBody)
		if err != nil {
			logger.Warn("Failed to create a request for Trivy api", log.Err(err))
			return
		}

		// if the user hasn't disabled metrics, send the anonymous information as headers
		if !v.telemetryDisabled {
			req.Header.Set("Trivy-Identifier", uniqueIdentifier())
			req.Header.Set("Trivy-Command", strings.Join(args, " "))
			req.Header.Set("Trivy-OS", runtime.GOOS)
			req.Header.Set("Trivy-Arch", runtime.GOARCH)
		}

		req.Header.Set("User-Agent", fmt.Sprintf("trivy/%s", v.currentVersion))
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			logger.Debug("Failed getting response from Trivy api", log.Err(err))
			return
		}

		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&v.latestVersion); err != nil {
			logger.Debug("Failed to decode the Trivy response", log.Err(err))
			return
		}

		// enable priting if update allowed and quiet mode is not set
		if !v.skipUpdateCheck && !v.quiet {
			v.responseReceived = true
		}
		logger.Debug("Version check completed", log.String("latest_version", v.latestVersion.Trivy.LatestVersion))
		v.done = true
	}()
}

// PrintNotices prints any announcements or warnings
// to the output writer, most likely stderr
func (v *VersionChecker) PrintNotices(output io.Writer) {
	if !v.responseReceived {
		return
	}

	logger := log.WithPrefix("notification")
	logger.Debug("Printing notices")
	var notices []string

	notices = append(notices, v.Warnings()...)
	for _, announcement := range v.Announcements() {
		if time.Now().Before(announcement.ToDate) && time.Now().After(announcement.FromDate) {
			notices = append(notices, announcement.Announcement)
		}
	}

	cv, err := semver.Parse(strings.TrimPrefix(v.currentVersion, "v"))
	if err != nil {
		return
	}

	lv, err := semver.Parse(strings.TrimPrefix(v.LatestVersion(), "v"))
	if err != nil {
		return
	}

	if cv.LessThan(lv) {
		notices = append(notices, fmt.Sprintf("Version %s of Trivy is now available, current version is %s", lv, cv))
	}

	if len(notices) > 0 {
		fmt.Fprintf(output, "\n📣 \x1b[34mNotices:\x1b[0m\n")
		for _, notice := range notices {
			fmt.Fprintf(output, "  - %s\n", notice)
		}
		fmt.Fprintln(output)
		fmt.Fprintln(output, "To suppress version checks, run Trivy scans with the --skip-version-check flag")
		fmt.Fprintln(output)
	}
}

func (v *VersionChecker) LatestVersion() string {
	if v.responseReceived {
		return v.latestVersion.Trivy.LatestVersion
	}
	return ""
}

func (v *VersionChecker) Announcements() []announcement {
	if v.responseReceived {
		return v.latestVersion.Announcements
	}
	return nil
}

func (v *VersionChecker) Warnings() []string {
	if v.responseReceived {
		return v.latestVersion.Warnings
	}
	return nil
}

// getFlags returns the just the flag portion without the values
func getFlags(args []string) []string {
	var flags []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, strings.Split(arg, "=")[0])
		}
	}
	return flags
}

func (fd *flexibleTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		return nil
	}

	// Try parsing with time component
	layouts := []string{
		time.RFC3339,
		"2006-01-02",
		time.RFC1123,
	}

	var err error
	for _, layout := range layouts {
		var t time.Time
		t, err = time.Parse(layout, s)
		if err == nil {
			fd.Time = t
			return nil
		}
	}

	return fmt.Errorf("unable to parse date: %s", s)
}
