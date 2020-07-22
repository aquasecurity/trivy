package ospkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/aquasecurity/trivy/rpc/common"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

func TestMain(m *testing.M) {
	_ = log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestServer_Detect(t *testing.T) {
	type args struct {
		req *proto.OSDetectRequest
	}
	tests := []struct {
		name                string
		args                args
		detectExpectation   ospkg.DetectExpectation
		fillInfoExpectation vulnerability.OperationFillInfoExpectation
		wantRes             *proto.DetectResponse
		wantErr             string
	}{
		{
			name: "happy path",
			args: args{
				req: &proto.OSDetectRequest{
					OsFamily: "alpine",
					OsName:   "3.10.2",
					Packages: []*common.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detectExpectation: ospkg.DetectExpectation{
				Args: ospkg.DetectInput{
					OSFamily: "alpine",
					OSName:   "3.10.2",
					Pkgs: []ftypes.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				ReturnArgs: ospkg.DetectOutput{
					Eosl: false,
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2019-0001",
							PkgName:         "musl",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "HIGH",
							},
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
						},
					},
				},
			},
			fillInfoExpectation: vulnerability.OperationFillInfoExpectation{
				Args: vulnerability.OperationFillInfoArgs{
					Vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2019-0001",
							PkgName:         "musl",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "HIGH",
							},
							Layer: ftypes.Layer{
								Digest: "sha256:154ad0735c360b212b167f424d33a62305770a1fcfb6363882f5c436cfbd9812",
								DiffID: "sha256:b2a1a2d80bf0c747a4f6b0ca6af5eef23f043fcdb1ed4f3a3e750aef2dc68079",
							},
						},
					},
				},
			},
			wantRes: &proto.DetectResponse{
				Vulnerabilities: []*common.Vulnerability{
					{
						VulnerabilityId: "CVE-2019-0001",
						PkgName:         "musl",
						Severity:        common.Severity_HIGH,
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
				req: &proto.OSDetectRequest{
					OsFamily: "alpine",
					OsName:   "3.10.2",
					Packages: []*common.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detectExpectation: ospkg.DetectExpectation{
				Args: ospkg.DetectInput{
					OSFamily: "alpine",
					OSName:   "3.10.2",
					Pkgs: []ftypes.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				ReturnArgs: ospkg.DetectOutput{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect vulnerabilities of OS packages: error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := ospkg.NewMockDetector([]ospkg.DetectExpectation{tt.detectExpectation})
			mockVulnClient := new(vulnerability.MockOperation)
			mockVulnClient.ApplyFillInfoExpectation(tt.fillInfoExpectation)

			s := NewServer(mockDetector, mockVulnClient)
			gotRes, err := s.Detect(context.TODO(), tt.args.req)
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
