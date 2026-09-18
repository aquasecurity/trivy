package test

// These tests cover aquasecurity/trivy#11117 and #11118. The canonical
// built-in checks live in trivy-checks (see aquasecurity/trivy-checks#635);
// testdata/tls-policy loads the updated rules so Trivy still proves that
// only TLS 1.0 policies are outdated.

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
)

func newTLSPolicyScanner() *cloudformation.Scanner {
	return cloudformation.New(
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyFilesystem(os.DirFS("testdata/tls-policy")),
		rego.WithPolicyDirs("."),
	)
}

func TestAWS0112SAMAPISecureTLSPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		wantFail bool
	}{
		{
			name:     "TLS_1_0 is outdated",
			policy:   "TLS_1_0",
			wantFail: true,
		},
		{
			name:     "legacy TLS_1_2 is secure",
			policy:   "TLS_1_2",
			wantFail: false,
		},
		{
			name:     "TLS 1.2+ SecurityPolicy is not reported as outdated",
			policy:   "SecurityPolicy_TLS13_1_2_2021_06",
			wantFail: false,
		},
		{
			name:     "TLS 1.3 only SecurityPolicy is not reported as outdated",
			policy:   "SecurityPolicy_TLS13_1_3_2025_09",
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(map[string]string{
				"template.yaml": `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Example:
    Type: AWS::Serverless::Api
    Properties:
      Domain:
        SecurityPolicy: ` + tt.policy + `
      Name: Example
      StageName: Prod
`,
			})

			results, err := newTLSPolicyScanner().ScanFS(t.Context(), fsys, ".")
			require.NoError(t, err)

			assert.Equal(t, tt.wantFail, hasFailedID(results, "AWS-0112"))
		})
	}
}

func TestAWS0126ElasticsearchSecureTLSPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		wantFail bool
	}{
		{
			name:     "TLS 1.0 policy is outdated",
			policy:   "Policy-Min-TLS-1-0-2019-07",
			wantFail: true,
		},
		{
			name:     "TLS 1.2 policy is secure",
			policy:   "Policy-Min-TLS-1-2-2019-07",
			wantFail: false,
		},
		{
			name:     "FIPS TLS 1.2+ policy is not reported as outdated",
			policy:   "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08",
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(map[string]string{
				"template.yaml": `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Example:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainEndpointOptions:
        TLSSecurityPolicy: ` + tt.policy + `
`,
			})

			results, err := newTLSPolicyScanner().ScanFS(t.Context(), fsys, ".")
			require.NoError(t, err)

			assert.Equal(t, tt.wantFail, hasFailedID(results, "AWS-0126"))
		})
	}
}

func hasFailedID(results scan.Results, id string) bool {
	for _, result := range results.GetFailed() {
		if result.Rule().ID == id {
			return true
		}
	}
	return false
}
