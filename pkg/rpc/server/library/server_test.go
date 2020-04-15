package library

import (
	"context"
	"os"
	"testing"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/aquasecurity/trivy/rpc/common"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestServer_Detect(t *testing.T) {
	type args struct {
		req *proto.LibDetectRequest
	}
	tests := []struct {
		name                string
		args                args
		detectExpectation   library.OperationDetectExpectation
		fillInfoExpectation vulnerability.FillInfoExpectation
		wantRes             *proto.DetectResponse
		wantErr             string
	}{
		{
			name: "happy path",
			args: args{
				req: &proto.LibDetectRequest{
					ImageName: "alpine:3.10",
					FilePath:  "app/Pipfile.lock",
					Libraries: []*common.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
			},
			detectExpectation: library.OperationDetectExpectation{
				Args: library.OperationDetectArgs{
					FilePath: "app/Pipfile.lock",
					Pkgs: []ftypes.LibraryInfo{
						{
							Library: ptypes.Library{Name: "django", Version: "3.0.0"},
						},
					},
				},
				Returns: library.OperationDetectReturns{
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "test",
							InstalledVersion: "1",
							FixedVersion:     "2",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "title",
								Description: "description",
								Severity:    "MEDIUM",
								References:  []string{"http://example.com"},
							},
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
						},
					},
				},
			},
			fillInfoExpectation: vulnerability.FillInfoExpectation{
				Args: vulnerability.FillInfoArgs{
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2019-0001",
							PkgName:          "test",
							InstalledVersion: "1",
							FixedVersion:     "2",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "title",
								Description: "description",
								Severity:    "MEDIUM",
								References:  []string{"http://example.com"},
							},
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
						},
					},
					Light: false,
				},
			},
			wantRes: &proto.DetectResponse{
				Vulnerabilities: []*common.Vulnerability{
					{
						VulnerabilityId:  "CVE-2019-0001",
						PkgName:          "test",
						InstalledVersion: "1",
						FixedVersion:     "2",
						Title:            "title",
						Description:      "description",
						Severity:         common.Severity_MEDIUM,
						References:       []string{"http://example.com"},
						Layer: &common.Layer{
							Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
							DiffId: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
						},
					},
				},
			},
		},
		{
			name: "Detect returns an error",
			args: args{
				req: &proto.LibDetectRequest{
					ImageName: "alpine:3.10",
					FilePath:  "app/Pipfile.lock",
					Libraries: []*common.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
			},
			detectExpectation: library.OperationDetectExpectation{
				Args: library.OperationDetectArgs{
					FilePath: "app/Pipfile.lock",
					Pkgs: []ftypes.LibraryInfo{
						{Library: ptypes.Library{Name: "django", Version: "3.0.0"}},
					},
				},
				Returns: library.OperationDetectReturns{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect library vulnerabilities",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(library.MockOperation)
			mockDetector.ApplyDetectExpectation(tt.detectExpectation)
			mockVulnClient := new(vulnerability.MockOperation)
			mockVulnClient.ApplyFillInfoExpectation(tt.fillInfoExpectation)

			s := NewServer(mockDetector, mockVulnClient)
			ctx := context.TODO()
			gotRes, err := s.Detect(ctx, tt.args.req)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantRes, gotRes, tt.name)
			mockDetector.AssertExpectations(t)
			mockVulnClient.AssertExpectations(t)
		})
	}
}
