package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
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

var (
	updatesApi       = "https://api.trivy.cloud/check"
	responseRecieved atomic.Bool
	currentVersion   string
	latestVersion    updateResponse
)

// CheckForNotices makes a best efforts request to determine the
// latest version and any announcements
func CheckForNotices(ctx context.Context, version string, args []string) {
	currentVersion = version

	logger := log.WithPrefix("notices")

	go func() {
		args = getFlags(args)

		logger.Debug("Requesting latest details")
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, updatesApi, http.NoBody)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to create a request: %v", err))
			return
		}
		req.Header.Set("-x-trivy-identifier", uniqueIdentifier())
		req.Header.Set("-x-trivy-command", strings.Join(args, " "))
		req.Header.Set("-x-trivy-os", runtime.GOOS)
		req.Header.Set("-x-trivy-arch", runtime.GOARCH)
		req.Header.Set("User-Agent", "trivy/"+currentVersion)
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			logger.Warn(fmt.Sprintf("Failed to get the latest version: %v", err))
			return
		}

		logger.Debug("Details received, storing for later")
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&latestVersion); err != nil {
			logger.Warn(fmt.Sprintf("Failed to decode the response: %v", err))
			return
		}
		responseRecieved.Store(true)
		logger.Debug("Details ready for printing")
	}()
}

// PrintNotices prints any announcements or warnings
// to the output writer, most likely stderr
func PrintNotices(output io.Writer) {
	if !responseRecieved.Load() {
		return
	}
	var notices []string

	notices = append(notices, latestVersion.Warnings...)
	for _, announcement := range latestVersion.Announcements {
		if time.Now().Before(announcement.ToDate) && time.Now().After(announcement.FromDate) {
			notices = append(notices, announcement.Announcement)
		}
	}

	if currentVersion != latestVersion.Trivy.LatestVersion {
		notices = append(notices, fmt.Sprintf("Version %s of Trivy is now available, current version is %s", latestVersion.Trivy.LatestVersion, currentVersion))
	}

	if len(notices) > 0 {
		fmt.Fprintf(output, "\n📣 \x1b[34mNotices:\x1b[0m\n")
		for _, notice := range notices {
			fmt.Fprintf(output, "  - %s\n", notice)
		}
		fmt.Fprintln(output)
		fmt.Fprintln(output, "To suppress version checks, run Trivy scans with the --no-notices flag")
		fmt.Fprintln(output)
	}
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
