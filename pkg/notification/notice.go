package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/app"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type VersionChecker struct {
	updatesApi  string
	commandName string
	cliOptions  *flag.Options

	done             bool
	responseReceived bool
	currentVersion   string
	latestVersion    updateResponse
}

// NewVersionChecker creates a new VersionChecker with the default
// updates API URL.
func NewVersionChecker(commandName string, cliOptions *flag.Options) *VersionChecker {
	v := &VersionChecker{
		updatesApi:     "https://check.trivy.dev/updates",
		currentVersion: app.Version(),
		commandName:    commandName,
		cliOptions:     cliOptions,
	}

	return v
}

// RunUpdateCheck makes a best efforts request to determine the
// latest version and any announcements
// Logic:
// 1. if skipUpdateCheck is true AND telemetryDisabled are both true, skip the request
// 2. if skipUpdateCheck is true AND telemetryDisabled is false, run check with metric details but suppress output
// 3. if skipUpdateCheck is false AND telemetryDisabled is true, run update check but don't send any metric identifiers
func (v *VersionChecker) RunUpdateCheck(ctx context.Context) {
	logger := log.WithPrefix("notification")

	if v.cliOptions.SkipVersionCheck && v.cliOptions.DisableTelemetry {
		logger.Debug("Skipping update check and metric ping")
		return
	}

	go func() {
		logger.Debug("Running version check")
		commandParts := v.getFlags()
		client := xhttp.ClientWithContext(ctx, xhttp.WithTimeout(3*time.Second))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.updatesApi, http.NoBody)
		if err != nil {
			logger.Warn("Failed to create a request for Trivy api", log.Err(err))
			return
		}

		// if the user hasn't disabled metrics, send the anonymous information as headers
		if !v.cliOptions.DisableTelemetry {
			req.Header.Set("Trivy-Identifier", uniqueIdentifier())
			req.Header.Set("Trivy-Command", v.commandName)
			req.Header.Set("Trivy-Flags", commandParts)
			req.Header.Set("Trivy-OS", runtime.GOOS)
			req.Header.Set("Trivy-Arch", runtime.GOARCH)
		}

		req.Header.Set("User-Agent", fmt.Sprintf("trivy/%s", v.currentVersion))
		resp, err := client.Do(req)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				logger.Debug("Failed getting response from Trivy api", log.Err(err))
			}
			return
		} else if resp.StatusCode != http.StatusOK {
			logger.Debug("Unexpected status code from Trivy api", log.Int("status_code", resp.StatusCode))
			return
		}

		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&v.latestVersion); err != nil {
			logger.Debug("Failed to decode the Trivy response", log.Err(err))
			return
		}

		// enable priting if update allowed and quiet mode is not set
		if !v.cliOptions.SkipVersionCheck && !v.cliOptions.Quiet {
			v.responseReceived = true
		}
		logger.Debug("Version check completed", log.String("latest_version", v.latestVersion.Trivy.LatestVersion))
		v.done = true
	}()
}

// PrintNotices prints any announcements or warnings
// to the output writer, most likely stderr
func (v *VersionChecker) PrintNotices(ctx context.Context, output io.Writer) {
	if !v.responseReceived {
		return
	}

	logger := log.WithPrefix("notification")
	var notices []string

	cv, err := v.CurrentVersion()
	if err != nil {
		return
	}

	lv, err := v.LatestVersion()
	if err != nil {
		return
	}

	notices = append(notices, v.Warnings()...)
	for _, announcement := range v.Announcements() {
		if announcement.shouldDisplay(ctx, cv) {
			notices = append(notices, announcement.Announcement)
		}
	}

	if cv.LessThan(lv) {
		notices = append(notices, fmt.Sprintf("Version %s of Trivy is now available, current version is %s", lv, cv))
	}

	if len(notices) > 0 {
		logger.Debug("Printing notices")
		fmt.Fprintf(output, "\n📣 \x1b[34mNotices:\x1b[0m\n")
		for _, notice := range notices {
			fmt.Fprintf(output, "  - %s\n", notice)
		}
		fmt.Fprintln(output)
		fmt.Fprintln(output, "To suppress version checks, run Trivy scans with the --skip-version-check flag")
		fmt.Fprintln(output)
	}
}

func (v *VersionChecker) CurrentVersion() (semver.Version, error) {
	current, err := semver.Parse(strings.TrimPrefix(v.currentVersion, "v"))
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to parse current version: %w", err)
	}
	return current, nil
}

func (v *VersionChecker) LatestVersion() (semver.Version, error) {
	if v.responseReceived {
		latest, err := semver.Parse(strings.TrimPrefix(v.latestVersion.Trivy.LatestVersion, "v"))
		if err != nil {
			return semver.Version{}, fmt.Errorf("failed to parse latest version: %w", err)
		}
		return latest, nil
	}
	return semver.Version{}, errors.New("no response received from version check")
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

func (v *VersionChecker) getFlags() string {
	var flags []string
	for _, f := range v.cliOptions.GetUsedFlags() {
		name := f.GetName()
		if name == "" {
			continue // Skip flags without a name
		}
		value := lo.Ternary(!f.IsTelemetrySafe(), "***", getFlagValue(f))

		flags = append(flags, fmt.Sprintf("--%s=%s", name, value))
	}
	return strings.Join(flags, " ")
}

func getFlagValue(f flag.Flagger) string {
	type flagger[T flag.FlagType] interface {
		Value() T
	}
	switch ff := f.(type) {
	case flagger[string]:
		return ff.Value()
	case flagger[int]:
		return strconv.Itoa(ff.Value())
	case flagger[float64]:
		return fmt.Sprintf("%f", ff.Value())
	case flagger[bool]:
		return strconv.FormatBool(ff.Value())
	case flagger[time.Duration]:
		return ff.Value().String()
	case flagger[[]string]:
		return strings.Join(ff.Value(), ",")
	default:
		return "***" // Default case for unsupported types
	}
}
