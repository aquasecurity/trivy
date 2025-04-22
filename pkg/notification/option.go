package notification

type Option func(*VersionChecker)

// WithUpdatesApi sets the updates API URL
func WithUpdatesApi(updatesApi string) Option {
	return func(v *VersionChecker) {
		v.updatesApi = updatesApi
	}
}

// WithCurrentVersion sets the current version
func WithCurrentVersion(version string) Option {
	return func(v *VersionChecker) {
		v.currentVersion = version
	}
}

func WithSkipUpdateCheck(skipUpdateCheck bool) Option {
	return func(v *VersionChecker) {
		v.skipUpdateCheck = skipUpdateCheck
	}
}

// WithQuietMode sets the quiet mode when the user is using the --quiet flag
func WithQuietMode(quiet bool) Option {
	return func(v *VersionChecker) {
		v.quiet = quiet
	}
}

// WithTelemetryDisabled sets the telemetry disabled flag
func WithTelemetryDisabled(telemetryDisabled bool) Option {
	return func(v *VersionChecker) {
		v.telemetryDisabled = telemetryDisabled
	}
}
