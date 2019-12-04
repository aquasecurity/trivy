package library

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/mock"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
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
		filePath string
		libs     []ptypes.Library
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
		req *proto.LibDetectRequest
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
				req: &proto.LibDetectRequest{
					FilePath: "app/Pipfile.lock",
					Libraries: []*proto.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
			},
			detect: detect{
				input: detectInput{
					filePath: "app/Pipfile.lock",
					libs: []ptypes.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
				output: detectOutput{
					vulns: []types.DetectedVulnerability{
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
			wantRes: &proto.DetectResponse{
				Vulnerabilities: []*proto.Vulnerability{
					{
						VulnerabilityId:  "CVE-2019-0001",
						PkgName:          "test",
						InstalledVersion: "1",
						FixedVersion:     "2",
						Title:            "title",
						Description:      "description",
						Severity:         proto.Severity_MEDIUM,
						References:       []string{"http://example.com"},
					},
				},
			},
		},
		{
			name: "Detect returns an error",
			args: args{
				req: &proto.LibDetectRequest{
					FilePath: "app/Pipfile.lock",
					Libraries: []*proto.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
			},
			detect: detect{
				input: detectInput{
					filePath: "app/Pipfile.lock",
					libs: []ptypes.Library{
						{Name: "django", Version: "3.0.0"},
					},
				},
				output: detectOutput{
					err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect library vulnerabilities",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(library.MockDetector)
			mockDetector.On("Detect", tt.detect.input.filePath, tt.detect.input.libs).Return(
				tt.detect.output.vulns, tt.detect.output.err)

			mockVulnClient := new(vulnerability.MockVulnClient)
			mockVulnClient.On("FillInfo", mock.Anything, mock.Anything)

			s := &Server{
				detector:   mockDetector,
				vulnClient: mockVulnClient,
			}
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
		})
	}
}
