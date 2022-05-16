package report_test

import (
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/defsec/pkg/scan"
	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestMisconfigRenderer(t *testing.T) {

	tests := []struct {
		name               string
		input              []types.DetectedMisconfiguration
		want               string
		includeNonFailures bool
	}{
		{
			name:               "no results",
			input:              nil,
			want:               "",
			includeNonFailures: false,
		},
		{
			name: "single result",
			input: []types.DetectedMisconfiguration{
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
			want: `HIGH: Oh no, a bad config.
════════════════════════════════════════
Your config file is not good.

See https://google.com/search?q=bad%20config
────────────────────────────────────────


`,
			includeNonFailures: false,
		},
		{
			name: "single result with code",
			input: []types.DetectedMisconfiguration{
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
						Code: scan.Code{
							Lines: []scan.Line{
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
			want: `HIGH: Oh no, a bad config.
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
			includeNonFailures: false,
		},
		{
			name: "multiple results",
			input: []types.DetectedMisconfiguration{
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
						Code: scan.Code{
							Lines: []scan.Line{
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
			want: `FAIL: HIGH: Oh no, a bad config.
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
			includeNonFailures: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			renderer := report.NewMisconfigRenderer("my-file", test.input, test.includeNonFailures, false)
			assert.Equal(t, test.want, strings.ReplaceAll(renderer.Render(), "\r\n", "\n"))
		})
	}
}
