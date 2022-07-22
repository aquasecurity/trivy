package predicate_test

import (
	"bytes"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	reportCosignVuln "github.com/aquasecurity/trivy/pkg/report/predicate"
	fake "k8s.io/utils/clock/testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
)

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
					URI:     "pkg:github/aquasecurity/trivy@dev",
					Version: "dev",
					DB: attestation.DB{
						URI:     "",
						Version: "",
					},
					// TODO:
					//Result: nil,
				},
				Metadata: attestation.Metadata{
					ScanStartedOn:  time.Date(2022, time.July, 22, 12, 20, 30, 5, time.UTC),
					ScanFinishedOn: time.Date(2022, time.July, 22, 12, 20, 30, 5, time.UTC),
				},
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

			output := bytes.NewBuffer(nil)

			clock := fake.NewFakeClock(time.Date(2022, 7, 22, 12, 20, 30, 5, time.UTC))
			writer := reportCosignVuln.NewWriter(output, "dev", reportCosignVuln.WithClock(clock))

			err := writer.Write(inputResults)
			assert.NoError(t, err)

			var got attestation.CosignVulnPredicate
			err = json.Unmarshal(output.Bytes(), &got)
			assert.NoError(t, err, "invalid json written")

			assert.Equal(t, tc.want.Scanner.URI, got.Scanner.URI, tc.name)
			assert.Equal(t, tc.want.Scanner.Version, got.Scanner.Version, tc.name)
			assert.Equal(t, tc.want.Metadata, got.Metadata, tc.name)

			var gotResult types.Report
			j, _ := json.Marshal(got.Scanner.Result)
			_ = json.Unmarshal(j, &gotResult)

			assert.Equal(t, tc.wantResult, gotResult, tc.name)
		})
	}
}
