package ospkg

import (
	"context"
	"os"
	"testing"

	ospkg2 "github.com/aquasecurity/trivy/pkg/detector/ospkg"

	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/fanal/analyzer"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	code := m.Run()
	os.Exit(code)
}

func TestServer_Detect(t *testing.T) {
	type detectInput struct {
		osFamily string
		osName   string
		pkgs     []analyzer.Package
	}
	type detectOutput struct {
		vulns []types.DetectedVulnerability
		err   error
	}
	type detect struct {
		input  detectInput
		output detectOutput
	}

	type args struct {
		req *proto.OSDetectRequest
	}
	tests := []struct {
		name    string
		args    args
		detect  detect
		wantRes *proto.DetectResponse
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				req: &proto.OSDetectRequest{
					OsFamily: "alpine",
					OsName:   "3.10.2",
					Packages: []*proto.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detect: detect{
				input: detectInput{
					osFamily: "alpine",
					osName:   "3.10.2",
					pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				output: detectOutput{
					vulns: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2019-0001",
							PkgName:         "musl",
							Vulnerability: dbTypes.Vulnerability{
								Severity: "HIGH",
							}},
					},
				},
			},
			wantRes: &proto.DetectResponse{
				Vulnerabilities: []*proto.Vulnerability{
					{
						VulnerabilityId: "CVE-2019-0001",
						PkgName:         "musl",
						Severity:        proto.Severity_HIGH,
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
					Packages: []*proto.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
			},
			detect: detect{
				input: detectInput{
					osFamily: "alpine",
					osName:   "3.10.2",
					pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				output: detectOutput{
					err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect OS package vulnerabilities",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(ospkg2.MockDetector)
			mockDetector.On("Detect", tt.detect.input.osFamily, tt.detect.input.osName,
				tt.detect.input.pkgs).Return(tt.detect.output.vulns, tt.detect.output.err)

			mockVulnClient := new(vulnerability.MockVulnClient)
			mockVulnClient.On("FillInfo", mock.Anything, mock.Anything)

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
