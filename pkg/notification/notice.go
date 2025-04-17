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

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

type versionInfo struct {
	LatestVersion string    `json:"latest_version"`
	LatestDate    time.Time `json:"latest_date"`
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
	updatesApi      string
	skipUpdateCheck bool
	quiet           bool
	disableMetrics  bool

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
		updatesApi:     "https://api.trivy.cloud/updates",
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
// 1. if skipUpdateCheck is true AND metricsDisabled are both true, skip the request
// 2. if skipUpdateCheck is true AND metricsDisabled is false, run check with metric details but suppress output
// 3. if skipUpdateCheck is false AND metricsDisabled is true, run update check but don't send any metric identifiers
func (v *VersionChecker) RunUpdateCheck(ctx context.Context, args []string) {
	logger := log.WithPrefix("notification")

	if v.skipUpdateCheck && v.disableMetrics {
		logger.Debug("Skipping update check and metric ping")
		return
	}

	go func() {
		args = getFlags(args)
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.updatesApi, http.NoBody)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to create a request for Trivy api: %v", err))
			return
		}

		// if the user hasn't disabled metrics, send the anonymous information as headers
		if !v.disableMetrics {
			req.Header.Set("-x-trivy-identifier", uniqueIdentifier())
			req.Header.Set("-x-trivy-command", strings.Join(args, " "))
			req.Header.Set("-x-trivy-os", runtime.GOOS)
			req.Header.Set("-x-trivy-arch", runtime.GOARCH)
		}

		req.Header.Set("User-Agent", fmt.Sprintf("trivy/%s", v.currentVersion))
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			logger.Debug("Failed getting response from Trivy api", log.Err(err))
			return
		}

		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&v.latestVersion); err != nil {
			logger.Debug(fmt.Sprintf("Failed to decode the Trivy response: %v", err))
			return
		}

		// enable priting if update allowed and quiet mode is not set
		if !v.skipUpdateCheck && !v.quiet {
			v.responseReceived = true
		}
		v.done = true
	}()
}

// PrintNotices prints any announcements or warnings
// to the output writer, most likely stderr
func (v *VersionChecker) PrintNotices(output io.Writer) {
	if !v.responseReceived {
		return
	}

	var notices []string

	notices = append(notices, v.latestVersion.Warnings...)
	for _, announcement := range v.latestVersion.Announcements {
		if time.Now().Before(announcement.ToDate) && time.Now().After(announcement.FromDate) {
			notices = append(notices, announcement.Announcement)
		}
	}

	if v.currentVersion != v.latestVersion.Trivy.LatestVersion {
		notices = append(notices, fmt.Sprintf("Version %s of Trivy is now available, current version is %s", v.latestVersion.Trivy.LatestVersion, v.currentVersion))
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
