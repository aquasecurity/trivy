package client_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
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

	versionInfo := types.VersionInfo{
		Version: "0.50.0",
		VulnerabilityDB: &metadata.Metadata{
			Version:      2,
			UpdatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NextUpdate:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			DownloadedAt: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	tests := []struct {
		name          string
		customHeaders http.Header
		args          args
		expectation   *rpc.ScanResponse
		versionInfo   types.VersionInfo
		want          types.ScanResponse
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
					PkgTypes: []string{"os"},
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
								LastModifiedDate: &timestamppb.Timestamp{
									Seconds: 1577840460,
								},
								PublishedDate: &timestamppb.Timestamp{
									Seconds: 978310860,
								},
							},
						},
					},
				},
			},
			versionInfo: versionInfo,
			want: types.ScanResponse{
				Results: types.Results{
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
									Custom:           nil,
								},
								SeveritySource: "nvd",
								Layer: ftypes.Layer{
									DiffID: "sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10",
								},
								Custom: nil,
							},
						},
					},
				},
				OS: ftypes.OS{
					Family: "alpine",
					Name:   "3.11",
					Eosl:   true,
				},
				ServerInfo: versionInfo,
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
					PkgTypes: []string{"os"},
				},
			},
			wantErr: "failed to detect vulnerabilities via RPC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle /version endpoint
				if strings.HasSuffix(r.URL.Path, "/version") {
					w.Header().Set("Content-Type", "application/json")
					if lo.IsEmpty(tt.versionInfo) {
						w.WriteHeader(http.StatusNotFound)
					} else {
						_ = json.NewEncoder(w).Encode(tt.versionInfo)
					}
					return
				}

				// Handle RPC scan endpoint
				if tt.expectation == nil {
					e := map[string]any{
						"code": "not_found",
						"msg":  "expectation is empty",
					}
					b, _ := json.Marshal(e)
					w.WriteHeader(http.StatusBadGateway)
					_, _ = w.Write(b)
					return
				}
				b, err := protojson.Marshal(tt.expectation)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "json marshaling error: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(b)
			}))
			defer ts.Close()
			rpcClient := rpc.NewScannerJSONClient(ts.URL, ts.Client())

			s := client.NewTestService(ts.URL, tt.customHeaders, rpcClient, ts.Client())

			gotResponse, err := s.Scan(t.Context(), tt.args.target, tt.args.imageID, tt.args.layerIDs, tt.args.options)

			if tt.wantErr != "" {
				require.Error(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, gotResponse)
		})
	}
}

func TestScanner_ScanServerInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
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
			httpClient := &http.Client{
				Transport: xhttp.NewTransport(xhttp.Options{Insecure: tt.insecure}).Build(),
			}
			rpcClient := rpc.NewScannerProtobufClient(ts.URL, httpClient)
			s := client.NewTestService(ts.URL, nil, rpcClient, httpClient)
			_, err := s.Scan(t.Context(), "dummy", "", nil, types.ScanOptions{})

			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestService_ServerVersion(t *testing.T) {
	versionInfo := types.VersionInfo{
		Version: "0.50.0",
		VulnerabilityDB: &metadata.Metadata{
			Version:      2,
			UpdatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NextUpdate:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			DownloadedAt: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	tests := []struct {
		name          string
		customHeaders http.Header
		serverHandler func(w http.ResponseWriter, r *http.Request)
		want          types.VersionInfo
	}{
		{
			name: "happy path",
			customHeaders: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(versionInfo)
			},
			want: versionInfo,
		},
		{
			name: "server returns 404",
			serverHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "server returns invalid JSON",
			serverHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("invalid json"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/version") {
					tt.serverHandler(w, r)
					return
				}
				// Handle RPC endpoint with empty response for scan
				w.Header().Set("Content-Type", "application/json")
				b, _ := protojson.Marshal(&rpc.ScanResponse{})
				_, _ = w.Write(b)
			}))
			defer ts.Close()

			rpcClient := rpc.NewScannerJSONClient(ts.URL, ts.Client())
			s := client.NewTestService(ts.URL, tt.customHeaders, rpcClient, ts.Client())

			// Call Scan which internally calls serverVersion
			resp, err := s.Scan(t.Context(), "test", "", nil, types.ScanOptions{})

			// When server version fetch fails, it's logged but not returned as an error
			require.NoError(t, err)
			assert.Equal(t, tt.want, resp.ServerInfo)
		})
	}
}
