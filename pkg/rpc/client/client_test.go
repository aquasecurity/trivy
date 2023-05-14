package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/common"
	rpc "github.com/aquasecurity/trivy/rpc/scanner"
)

func TestScanner_Scan(t *testing.T) {
	type args struct {
		target   string
		imageID  string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name          string
		customHeaders http.Header
		args          args
		expectation   *rpc.ScanResponse
		wantResults   types.Results
		wantOS        ftypes.OS
		wantEosl      bool
		wantErr       string
	}{
		{
			name: "happy path",
			customHeaders: http.Header{
				"Trivy-Token": []string{"foo"},
			},
			args: args{
				target:   "alpine:3.11",
				imageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType: []string{"os"},
				},
			},
			expectation: &rpc.ScanResponse{
				Os: &common.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				Results: []*rpc.Result{
					{
						Target: "alpine:3.11",
						Vulnerabilities: []*common.Vulnerability{
							{
								VulnerabilityId:  "CVE-2020-0001",
								PkgName:          "musl",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Title:            "DoS",
								Description:      "Denial os Service",
								Severity:         common.Severity_CRITICAL,
								References:       []string{"http://example.com"},
								SeveritySource:   "nvd",
								VendorSeverity: map[string]common.Severity{
									string(vulnerability.NVD):    common.Severity_MEDIUM,
									string(vulnerability.RedHat): common.Severity_MEDIUM,
								},
								Cvss: map[string]*common.CVSS{
									"nvd": {
										V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  7.2,
										V3Score:  7.8,
									},
									"redhat": {
										V2Vector: "AV:H/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  4.2,
										V3Score:  2.8,
									},
								},
								CweIds: []string{"CWE-78"},
								Layer: &common.Layer{
									DiffId: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
								},
								LastModifiedDate: &timestamp.Timestamp{
									Seconds: 1577840460,
								},
								PublishedDate: &timestamp.Timestamp{
									Seconds: 978310860,
								},
							},
						},
					},
				},
			},
			wantResults: types.Results{
				{
					Target: "alpine:3.11",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "musl",
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "DoS",
								Description: "Denial os Service",
								Severity:    "CRITICAL",
								References:  []string{"http://example.com"},
								VendorSeverity: dbTypes.VendorSeverity{
									vulnerability.NVD:    dbTypes.SeverityMedium,
									vulnerability.RedHat: dbTypes.SeverityMedium,
								},
								CVSS: dbTypes.VendorCVSS{
									"nvd": {
										V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  7.2,
										V3Score:  7.8,
									},
									"redhat": {
										V2Vector: "AV:H/AC:L/Au:N/C:C/I:C/A:C",
										V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
										V2Score:  4.2,
										V3Score:  2.8,
									},
								},
								CweIDs:           []string{"CWE-78"},
								LastModifiedDate: utils.MustTimeParse("2020-01-01T01:01:00Z"),
								PublishedDate:    utils.MustTimeParse("2001-01-01T01:01:00Z"),
							},
							SeveritySource: "nvd",
							Layer: ftypes.Layer{
								DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
							},
						},
					},
				},
			},
			wantOS: ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
				Eosl:   true,
			},
		},
		{
			name: "sad path: Scan returns an error",
			customHeaders: http.Header{
				"Trivy-Token": []string{"foo"},
			},
			args: args{
				target:   "alpine:3.11",
				imageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType: []string{"os"},
				},
			},
			wantErr: "failed to detect vulnerabilities via RPC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.expectation == nil {
					e := map[string]interface{}{
						"code": "not_found",
						"msg":  "expectation is empty",
					}
					b, _ := json.Marshal(e)
					w.WriteHeader(http.StatusBadGateway)
					w.Write(b)
					return
				}
				b, err := protojson.Marshal(tt.expectation)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "json marshalling error: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}))
			client := rpc.NewScannerJSONClient(ts.URL, ts.Client())

			s := NewScanner(ScannerOption{CustomHeaders: tt.customHeaders}, WithRPCClient(client))

			gotResults, gotOS, err := s.Scan(context.Background(), tt.args.target, tt.args.imageID, tt.args.layerIDs, tt.args.options)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.wantResults, gotResults)
			assert.Equal(t, tt.wantOS, gotOS)
		})
	}
}

func TestScanner_ScanServerInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	tests := []struct {
		name     string
		insecure bool
		wantErr  string
	}{
		{
			name:     "happy path",
			insecure: true,
		},
		{
			name:     "sad path",
			insecure: false,
			wantErr:  "failed to do request",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := rpc.NewScannerProtobufClient(ts.URL, &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: tt.insecure,
					},
				},
			})
			s := NewScanner(ScannerOption{Insecure: tt.insecure}, WithRPCClient(c))
			_, _, err := s.Scan(context.Background(), "dummy", "", nil, types.ScanOptions{})

			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
