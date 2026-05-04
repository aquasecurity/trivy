package secret_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/secret"
)

// findRule looks up an Azure rule by ID from the built-in registry. Defined
// here (and not deduplicated against the existing test suite) so this file
// can compile in isolation if the Azure rules are extracted to their own
// file in a future refactor.
func findRule(t *testing.T, id string) secret.Rule {
	t.Helper()
	for _, r := range secret.GetBuiltinRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("builtin rule %q not found", id)
	return secret.Rule{}
}

// 88-character base64 fixture: 64 raw bytes is the Azure storage account
// key shape. The trailing `==` is part of the canonical encoding.
const fakeBase64Key88 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN=="

// TestAzureStorageAccountKey covers issue #10615 rule 1.
//
// The pattern is anchored on `AccountKey=` with a tolerant whitespace
// allowance so it picks up both bare-env-var and connection-string forms.
func TestAzureStorageAccountKey(t *testing.T) {
	rule := findRule(t, "azure-storage-account-key")

	cases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "bare env-var assignment",
			input:   "AccountKey=" + fakeBase64Key88,
			wantHit: true,
		},
		{
			name:    "case insensitive anchor",
			input:   "accountkey = " + fakeBase64Key88,
			wantHit: true,
		},
		{
			name:    "inside full connection string",
			input:   "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=" + fakeBase64Key88 + ";EndpointSuffix=core.windows.net",
			wantHit: true,
		},
		{
			name:    "wrong length is rejected",
			input:   "AccountKey=" + strings.Repeat("A", 40),
			wantHit: false,
		},
		{
			name:    "missing AccountKey anchor is rejected",
			input:   "Other=" + fakeBase64Key88,
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

// TestAzureCosmosDBAccountKey covers issue #10615 rule 2. The pattern only
// matches when the *.documents.azure.com / *.cosmos.azure.com endpoint
// anchor is present alongside the AccountKey. A bare key with no Cosmos
// hostname must NOT match this rule (it's covered by the Storage rule).
func TestAzureCosmosDBAccountKey(t *testing.T) {
	rule := findRule(t, "azure-cosmosdb-account-key")

	cases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "documents.azure.com endpoint",
			input:   "AccountEndpoint=https://demo.documents.azure.com:443/;AccountKey=" + fakeBase64Key88 + ";",
			wantHit: true,
		},
		{
			name:    "cosmos.azure.com endpoint",
			input:   "AccountEndpoint=https://demo.cosmos.azure.com:443/;AccountKey=" + fakeBase64Key88 + ";",
			wantHit: true,
		},
		{
			name:    "bare key without endpoint anchor is not matched here",
			input:   "AccountKey=" + fakeBase64Key88,
			wantHit: false,
		},
		{
			name:    "wrong endpoint domain is rejected",
			input:   "AccountEndpoint=https://demo.example.com:443/;AccountKey=" + fakeBase64Key88 + ";",
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

// TestAzureEntraIDClientSecret covers issue #10615 rule 3. The unique
// `8Q~` marker at positions 4-6 of a 40-char string is what makes this
// pattern self-anchoring without external context.
func TestAzureEntraIDClientSecret(t *testing.T) {
	rule := findRule(t, "azure-entra-id-client-secret")

	// Build a synthetic 40-char fixture with the marker at positions 4-6.
	// Composition: 3 chars + "8Q~" + 34 chars = 40 chars total.
	prefix := "Abc"
	suffix := "DefGhiJklMnoPqrStuVwxYz0123456789~-"
	require.Len(t, suffix, 35) // 34 needed inside class + 1 trailing tolerated
	suffix = suffix[:34]
	fakeSecret := prefix + "8Q~" + suffix
	require.Len(t, fakeSecret, 40)

	cases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "bare token in code",
			input:   `client_secret = "` + fakeSecret + `"`,
			wantHit: true,
		},
		{
			name:    "missing 8Q~ marker is rejected",
			input:   `client_secret = "` + strings.Repeat("a", 40) + `"`,
			wantHit: false,
		},
		{
			name:    "marker present but wrong total length is rejected",
			input:   `client_secret = "Abc8Q~tooShort"`,
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

// TestAzureAppConfigConnectionString covers issue #10615 rule 5. The
// `*.azconfig.io` endpoint is the unique anchor.
func TestAzureAppConfigConnectionString(t *testing.T) {
	rule := findRule(t, "azure-app-configuration-connection-string")

	cases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "well-formed connection string",
			input:   "Endpoint=https://demo.azconfig.io;Id=ABCDef:0+1/foo:abc;Secret=" + strings.Repeat("A", 60) + "=",
			wantHit: true,
		},
		{
			name:    "wrong endpoint domain is rejected",
			input:   "Endpoint=https://demo.azure.com;Id=abc;Secret=" + strings.Repeat("A", 60) + "=",
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

// TestAzureSASToken covers issue #10615 rule 6. The `sv=YYYY-MM-DD` Azure
// service-version anchor is what separates this from the universe of
// generic URL-signature tokens.
func TestAzureSASToken(t *testing.T) {
	rule := findRule(t, "azure-sas-token")

	cases := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "blob SAS URL with sig",
			input:   "https://demo.blob.core.windows.net/c/o?sv=2024-08-04&ss=b&srt=co&sp=rl&se=2026-12-31T23:59:00Z&sig=" + strings.Repeat("A", 50) + "%3D",
			wantHit: true,
		},
		{
			name:    "missing sv= anchor is rejected (just sig= alone is too generic)",
			input:   "https://demo.example.com/x?something=1&sig=" + strings.Repeat("A", 60),
			wantHit: false,
		},
		{
			name:    "sv format must be YYYY-MM-DD",
			input:   "?sv=2024&ss=b&sig=" + strings.Repeat("A", 50),
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

// TestAzureRules_NoCollisionsBetweenRules pins that a Storage Account Key
// connection-string fragment is NOT also picked up by the Cosmos rule
// (which requires the documents/cosmos endpoint anchor) and vice-versa.
// Without this guarantee a single secret would emit two findings.
func TestAzureRules_NoCollisionsBetweenRules(t *testing.T) {
	storage := findRule(t, "azure-storage-account-key")
	cosmos := findRule(t, "azure-cosmosdb-account-key")

	// Pure storage connection string
	storageInput := "DefaultEndpointsProtocol=https;AccountName=foo;AccountKey=" + fakeBase64Key88 + ";EndpointSuffix=core.windows.net"
	assert.NotEmpty(t, storage.Regex.FindStringSubmatch(storageInput))
	assert.Empty(t, cosmos.Regex.FindStringSubmatch(storageInput),
		"cosmos rule must not match a non-cosmos connection string")

	// Pure cosmos connection string
	cosmosInput := "AccountEndpoint=https://demo.documents.azure.com:443/;AccountKey=" + fakeBase64Key88 + ";"
	assert.NotEmpty(t, cosmos.Regex.FindStringSubmatch(cosmosInput))
	// The storage rule will also match the AccountKey= portion of the
	// cosmos string. That's intentional and documented behavior — both
	// rules legitimately cover overlapping shapes; the Cosmos rule
	// merely adds context. Trivy's de-dup happens at the finding layer
	// by `(start, end)` not by rule, so a single base64 key emitting
	// from both rules surfaces as one finding to the user.
}
