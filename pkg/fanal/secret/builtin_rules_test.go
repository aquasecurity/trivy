package secret_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
)

// TestGitHubAppToken_BothFormats pins the regex update added in
// https://github.com/aquasecurity/trivy/issues/10591. GitHub started rolling
// out a new stateless `ghs_` installation token format on 2026-04-27 (~520
// chars, internal `_` separator). The rule must match both the legacy
// 36-char form and the new variable-length form, while keeping `ghu_` strict.
func TestGitHubAppToken_BothFormats(t *testing.T) {
	rule := findBuiltinRule(t, "github-app-token")

	// Build a JWT-like body that satisfies the new ghs_<APPID>_<JWT> shape:
	// `ghs_` + APPID + `_` + JWT.
	jwt := strings.Repeat("a", 100) + "_" + strings.Repeat("b", 200) + "_" + strings.Repeat("c", 200)

	cases := []struct {
		name     string
		input    string
		wantHit  bool
	}{
		{
			name:    "legacy ghs_ 36-char token still detected",
			input:   "ghs_" + strings.Repeat("0", 36),
			wantHit: true,
		},
		{
			name:    "legacy ghu_ 36-char token still detected",
			input:   "ghu_" + strings.Repeat("0", 36),
			wantHit: true,
		},
		{
			name:    "stateless ghs_<APPID>_<JWT> token detected (issue #10591)",
			input:   "ghs_123456_" + jwt,
			wantHit: true,
		},
		{
			name:    "stateless ghs_ with realistic ~520-char body",
			input:   "ghs_" + strings.Repeat("X", 520),
			wantHit: true,
		},
		{
			name:    "ghu_ with extra characters past 36 must NOT extend match (kept strict)",
			input:   "ghu_" + strings.Repeat("0", 30),
			wantHit: false, // too short; ghu_ stays at exactly 36
		},
		{
			name:    "ghs_ shorter than 36 chars is rejected",
			input:   "ghs_" + strings.Repeat("0", 20),
			wantHit: false,
		},
		{
			name:    "non-ghs/ghu prefix not matched",
			input:   "ghp_" + strings.Repeat("0", 36),
			wantHit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rule.Regex.FindStringSubmatch(tc.input)
			if tc.wantHit {
				require.NotEmpty(t, got, "expected match for %q", tc.input)
			} else {
				assert.Empty(t, got, "expected no match for %q, got %v", tc.input, got)
			}
		})
	}
}

func findBuiltinRule(t *testing.T, id string) secret.Rule {
	t.Helper()
	for _, r := range secret.GetBuiltinRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("builtin rule %q not found", id)
	return secret.Rule{}
}
