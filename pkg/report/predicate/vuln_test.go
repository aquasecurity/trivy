package predicate_test

import (
	"bytes"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
)

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/report"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		want          attestation.CosignVulnPredicate
		wantResult    types.Report
	}{
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
						VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
							vulnerability.NVD: dbTypes.SeverityHigh,
						},
					},
				},
			},
			want: attestation.CosignVulnPredicate{
				Scanner: attestation.Scanner{
					URI:     "pkg:github/aquasecurity/trivy@test",
					Version: "test",
					DB: attestation.DB{
						URI:     "",
						Version: "",
					},
					//
					//Result: nil,
				},
				// TODO: need test about time？
				//Metadata: attestation.Metadata{
				//	ScanStartedOn:  time.Time{},
				//	ScanFinishedOn: time.Time{},
				//},
			},
			wantResult: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				ArtifactType:  "",
				Metadata:      types.Metadata{},
				Results: []types.Result{
					{
						Target: "foojson",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-0001",
								PkgName:          "foo",
								InstalledVersion: "1.2.3",
								FixedVersion:     "3.4.5",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
								Vulnerability: dbTypes.Vulnerability{
									Title:       "foobar",
									Description: "baz",
									Severity:    "HIGH",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw := report.JSONWriter{}
			jsonWritten := bytes.Buffer{}
			jw.Output = &jsonWritten

			inputResults := types.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: types.Results{
					{
						Target:          "foojson",
						Vulnerabilities: tc.detectedVulns,
					},
				},
			}

			err := report.Write(inputResults, report.Option{
				AppVersion: "test", // TODO: is this ok?
				Format:     "cosign-vuln",
				Output:     &jsonWritten,
			})
			assert.NoError(t, err)

			var got attestation.CosignVulnPredicate
			err = json.Unmarshal(jsonWritten.Bytes(), &got)
			assert.NoError(t, err, "invalid json written")

			assert.Equal(t, tc.want.Scanner.URI, got.Scanner.URI, tc.name)
			assert.Equal(t, tc.want.Scanner.Version, got.Scanner.Version, tc.name)

			var gotResult types.Report
			j, _ := json.Marshal(got.Scanner.Result)
			_ = json.Unmarshal(j, &gotResult)

			assert.Equal(t, tc.wantResult, gotResult, tc.name)
		})
	}
}
