package update

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
	updatesApi     = "https://api.trivy.cloud/check"
	updated        atomic.Bool
	currentVersion string
	latestVersion  updateResponse
)

// CheckUpdate makes a best efforts request to determine the
// latest version and any announcements
func CheckUpdate(ctx context.Context, version string, args []string) {
	currentVersion = version

	go func() {
		args = getFlags(args)

		log.Debug("[version] Requesting latest details")
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, updatesApi, http.NoBody)
		if err != nil {
			log.Warnf("[version] Failed to create a request: %v", err)
			return
		}
		req.Header.Set("-x-trivy-identifier", uniqueIdentifier())
		req.Header.Set("-x-trivy-command", strings.Join(args, " "))
		req.Header.Set("-x-trivy-os", runtime.GOOS)
		req.Header.Set("-x-trivy-arch", runtime.GOARCH)
		req.Header.Set("User-Agent", "trivy/"+currentVersion)
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Warnf("[version] Failed to get the latest version: %v", err)
			return
		}

		log.Debug("[version] Details received, storing for later")
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&latestVersion); err != nil {
			log.Warnf("Failed to decode the response: %v", err)
			return
		}
		updated.Store(true)
		log.Debug("[version] Details ready for printing")
	}()
}

// NotifyUpdates prints any announcements or warnings
// to the output writer, most likely stderr
func NotifyUpdates(output io.Writer) {
	if !updated.Load() {
		// the update check didn't happen in time
		// or it had an error but we don't want to make noise
		// about it
		log.Debug("[version] Update check failed or didn't happen in time, check logs for more details")
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
		fmt.Fprintf(output, "\n 📣 \x1b[34mNotices:\x1b[0m\n")
		for _, notice := range notices {
			fmt.Fprintf(output, "  - %s\n", notice)
		}
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
