package library

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/detector/library"

	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
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
	type args struct {
		req *proto.LibDetectRequest
	}
	tests := []struct {
		name    string
		args    args
		detect  library.DetectExpectation
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
			detect: library.DetectExpectation{
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
			detect: library.DetectExpectation{
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
			mockDetector := library.NewMockDetector([]library.DetectExpectation{tt.detect})
			mockVulnClient := vulnerability.NewMockVulnClient()

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
