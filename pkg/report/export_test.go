package report

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/clock"
)

// Bridge to expose report internals to tests in the report_test package.

// SetFakeStartTime overrides the package-level process start time so that
// SARIF invocation timestamps are deterministic in tests.
func SetFakeStartTime(ctx context.Context) {
	processStartTime = clock.Now(ctx)
}

// ClearURI exports clearURI for testing.
var ClearURI = clearURI

// ToProperties exports toProperties for testing.
var ToProperties = toProperties

// ToUri exports toUri for testing.
var ToUri = toUri

// ToSarifErrorLevel exports toSarifErrorLevel for testing.
var ToSarifErrorLevel = toSarifErrorLevel

// PathToFileURI exports pathToFileURI for testing.
var PathToFileURI = pathToFileURI
