package ospkg

import (
	"context"
	"testing"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/detector"
	"github.com/stretchr/testify/mock"
)

type mockDetector struct {
	mock.Mock
}

func (_m *mockDetector) Detect(a context.Context, b *detector.OSDetectRequest) (*detector.DetectResponse, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	res, ok := ret0.(*detector.DetectResponse)
	if !ok {
		return nil, ret.Error(1)
	}
	return res, ret.Error(1)
}

func TestDetectClient_Detect(t *testing.T) {
	type detectInput struct {
		req *detector.OSDetectRequest
	}
	type detectOutput struct {
		res *detector.DetectResponse
		err error
	}
	type detect struct {
		input  detectInput
		output detectOutput
	}

	type fields struct {
		customHeaders CustomHeaders
	}
	type args struct {
		osFamily string
		osName   string
		pkgs     []analyzer.Package
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		detect  detect
		want    []types.DetectedVulnerability
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				customHeaders: CustomHeaders{
					"Trivy-Token": []string{"token"},
				},
			},
			args: args{
				osFamily: "alpine",
				osName:   "3.10.2",
				pkgs: []analyzer.Package{
					{
						Name:    "openssl",
						Version: "1.0.1e",
						Release: "1",
						Epoch:   0,
					},
				},
			},
			detect: detect{
				input: detectInput{
					req: &detector.OSDetectRequest{
						OsFamily: "alpine",
						OsName:   "3.10.2",
						Packages: []*detector.Package{
							{
								Name:    "openssl",
								Version: "1.0.1e",
								Release: "1",
								Epoch:   0,
							},
						},
					},
				},
				output: detectOutput{
					res: &detector.DetectResponse{
						Vulnerabilities: []*detector.Vulnerability{
							{
								VulnerabilityId:  "CVE-2019-0001",
								PkgName:          "bash",
								InstalledVersion: "1.2.3",
								FixedVersion:     "1.2.4",
								Title:            "RCE",
								Description:      "Remote Code Execution",
								Severity:         detector.Severity_HIGH,
							},
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2019-0001",
					PkgName:          "bash",
					InstalledVersion: "1.2.3",
					FixedVersion:     "1.2.4",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "RCE",
						Description: "Remote Code Execution",
						Severity:    "HIGH",
					},
				},
			},
		},
		{
			name:   "Detect returns an error",
			fields: fields{},
			args: args{
				osFamily: "alpine",
				osName:   "3.10.2",
				pkgs: []analyzer.Package{
					{
						Name:    "openssl",
						Version: "1.0.1e",
						Release: "1",
						Epoch:   0,
					},
				},
			},
			detect: detect{
				input: detectInput{
					req: &detector.OSDetectRequest{
						OsFamily: "alpine",
						OsName:   "3.10.2",
						Packages: []*detector.Package{
							{
								Name:    "openssl",
								Version: "1.0.1e",
								Release: "1",
								Epoch:   0,
							},
						},
					},
				},
				output: detectOutput{
					err: xerrors.New("error"),
				},
			},
			wantErr: "failed to detect vulnerabilities via RPC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(mockDetector)
			mockDetector.On("Detect", mock.Anything, tt.detect.input.req).Return(
				tt.detect.output.res, tt.detect.output.err)

			d := NewDetector(tt.fields.customHeaders, mockDetector)
			got, _, err := d.Detect(tt.args.osFamily, tt.args.osName, tt.args.pkgs)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
			mockDetector.AssertExpectations(t)
		})
	}
}
