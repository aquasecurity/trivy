package predicate_test

import (
	"bytes"
	"encoding/json"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/predicate"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	fake "k8s.io/utils/clock/testing"
	"testing"
	"time"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		want          predicate.CosignVulnPredicate
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
			want: predicate.CosignVulnPredicate{
				Scanner: predicate.Scanner{
					URI:     "pkg:github/aquasecurity/trivy@dev",
					Version: "dev",
					Result: types.Report{
						SchemaVersion: 2,
						ArtifactName:  "alpine:3.14",
						ArtifactType:  ftypes.ArtifactType(""),
						Metadata:      types.Metadata{},
						Results: types.Results{
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
				Metadata: predicate.Metadata{
					ScanStartedOn:  time.Date(2022, time.July, 22, 12, 20, 30, 5, time.UTC),
					ScanFinishedOn: time.Date(2022, time.July, 22, 12, 20, 30, 5, time.UTC),
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
			writer := predicate.NewWriter(output, "dev", predicate.WithClock(clock))

			err := writer.Write(inputResults)
			assert.NoError(t, err)

			var got predicate.CosignVulnPredicate
			err = json.Unmarshal(output.Bytes(), &got)
			assert.NoError(t, err, "invalid json written")

			assert.Equal(t, tc.want, got, tc.name)

		})
	}
}
