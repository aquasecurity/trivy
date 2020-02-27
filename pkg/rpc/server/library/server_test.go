package library

import (
	"context"
	"os"
	"testing"

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
		detectExpectation   library.DetectExpectation
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
			detectExpectation: library.DetectExpectation{
				Args: library.DetectInput{
					FilePath: "app/Pipfile.lock",
					Libs: []ptypes.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
				ReturnArgs: library.DetectOutput{
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
			detectExpectation: library.DetectExpectation{
				Args: library.DetectInput{
					FilePath: "app/Pipfile.lock",
					Libs: []ptypes.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
				ReturnArgs: library.DetectOutput{
					Err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect library vulnerabilities",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := library.NewMockDetector([]library.DetectExpectation{tt.detectExpectation})
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
