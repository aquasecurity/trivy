package table_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMisconfigRenderer(t *testing.T) {

	tests := []struct {
		name               string
		input              types.Result
		includeNonFailures bool
		want               string
	}{
		{
			name: "single result",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
					},
				},
			},
			includeNonFailures: false,
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────


`,
		},
		{
			name: "single result with code",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 0, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							Resource:  "",
							Provider:  "",
							Service:   "",
							StartLine: 0,
							EndLine:   0,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number: 1,
									},
									{
										Number:      2,
										Content:     "bad: true",
										Highlighted: "\x1b[37mbad:\x1b[0m true",
										IsCause:     true,
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number: 3,
									},
								},
							},
						},
					},
				},
			},
			includeNonFailures: false,
			want: `
my-file ()
==========
Tests: 1 (SUCCESSES: 0, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────
 my-file
────────────────────────────────────────
   1   
   2 [ bad: true
   3   
────────────────────────────────────────


`,
		},
		{
			name: "multiple results",
			input: types.Result{
				Target:         "my-file",
				MisconfSummary: &types.MisconfSummary{Successes: 1, Failures: 1, Exceptions: 0},
				Misconfigurations: []types.DetectedMisconfiguration{
					{
						ID:          "AVD-XYZ-0123",
						Title:       "Config file is bad",
						Description: "Your config file is not good.",
						Message:     "Oh no, a bad config.",
						Severity:    "HIGH",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "FAIL",
						CauseMetadata: ftypes.CauseMetadata{
							StartLine: 2,
							EndLine:   2,
							Code: ftypes.Code{
								Lines: []ftypes.Line{
									{
										Number: 1,
									},
									{
										Number:      2,
										Content:     "bad: true",
										Highlighted: "\x1b[37mbad:\x1b[0m true",
										IsCause:     true,
										FirstCause:  true,
										LastCause:   true,
									},
									{
										Number: 3,
									},
								},
							},
						},
					},
					{
						ID:          "AVD-XYZ-0456",
						Title:       "Config file is bad again",
						Description: "Your config file is still not good.",
						Message:     "Oh no, a bad config AGAIN.",
						Severity:    "MEDIUM",
						PrimaryURL:  "https://google.com/search?q=bad%20config",
						Status:      "PASS",
					},
				},
			},
			includeNonFailures: true,
			want: `
my-file ()
==========
Tests: 2 (SUCCESSES: 1, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

FAIL: HIGH: Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────
 my-file:2
────────────────────────────────────────
   1   
   2 [ bad: true
   3   
────────────────────────────────────────


PASS: MEDIUM: Oh no, a bad config AGAIN.
════════════════════════════════════════
Your config file is still not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────


`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			severities := []dbTypes.Severity{dbTypes.SeverityLow, dbTypes.SeverityMedium, dbTypes.SeverityHigh,
				dbTypes.SeverityCritical}
			renderer := table.NewMisconfigRenderer(test.input, severities, false, test.includeNonFailures, false)
			assert.Equal(t, test.want, strings.ReplaceAll(renderer.Render(), "\r\n", "\n"))
		})
	}
}
