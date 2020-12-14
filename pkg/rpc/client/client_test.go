package client

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/common"
	"github.com/aquasecurity/trivy/rpc/scanner"
)

type mockScanner struct {
	mock.Mock
}

type scanArgs struct {
	Ctx             context.Context
	CtxAnything     bool
	Request         *scanner.ScanRequest
	RequestAnything bool
}

type scanReturns struct {
	Res *scanner.ScanResponse
	Err error
}

type scanExpectation struct {
	Args    scanArgs
	Returns scanReturns
}

func (_m *mockScanner) ApplyScanExpectation(e scanExpectation) {
	var args []interface{}
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	if e.Args.RequestAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Request)
	}
	_m.On("Scan", args...).Return(e.Returns.Res, e.Returns.Err)
}

func (_m *mockScanner) ApplyScanExpectations(expectations []scanExpectation) {
	for _, e := range expectations {
		_m.ApplyScanExpectation(e)
	}
}

// Scan provides a mock function with given fields: Ctx, Request
func (_m *mockScanner) Scan(Ctx context.Context, Request *scanner.ScanRequest) (*scanner.ScanResponse, error) {
	ret := _m.Called(Ctx, Request)

	var r0 *scanner.ScanResponse
	if rf, ok := ret.Get(0).(func(context.Context, *scanner.ScanRequest) *scanner.ScanResponse); ok {
		r0 = rf(Ctx, Request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*scanner.ScanResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *scanner.ScanRequest) error); ok {
		r1 = rf(Ctx, Request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func TestScanner_Scan(t *testing.T) {
	type fields struct {
		customHeaders CustomHeaders
	}
	type args struct {
		target   string
		imageID  string
		layerIDs []string
		options  types.ScanOptions
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		scanExpectation scanExpectation
		wantResults     report.Results
		wantOS          *ftypes.OS
		wantEosl        bool
		wantErr         string
	}{
		{
			name: "happy path",
			fields: fields{
				customHeaders: CustomHeaders{
					"Trivy-Token": []string{"foo"},
				},
			},
			args: args{
				target:   "alpine:3.11",
				imageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType: []string{"os"},
				},
			},
			scanExpectation: scanExpectation{
				Args: scanArgs{
					CtxAnything: true,
					Request: &scanner.ScanRequest{
						Target:     "alpine:3.11",
						ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						BlobIds:    []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
						Options: &scanner.ScanOptions{
							VulnType: []string{"os"},
						},
					},
				},
				Returns: scanReturns{
					Res: &scanner.ScanResponse{
						Os: &common.OS{
							Family: "alpine",
							Name:   "3.11",
						},
						Eosl: true,
						Results: []*scanner.Result{
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
										References:       []string{"http://exammple.com"},
										SeveritySource:   "nvd",
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
				},
			},
			wantResults: report.Results{
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
								References:  []string{"http://exammple.com"},
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
			wantOS: &ftypes.OS{
				Family: "alpine",
				Name:   "3.11",
			},
			wantEosl: true,
		},
		{
			name: "sad path: Scan returns an error",
			fields: fields{
				customHeaders: CustomHeaders{
					"Trivy-Token": []string{"foo"},
				},
			},
			args: args{
				target:   "alpine:3.11",
				imageID:  "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
				layerIDs: []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
				options: types.ScanOptions{
					VulnType: []string{"os"},
				},
			},
			scanExpectation: scanExpectation{
				Args: scanArgs{
					CtxAnything: true,
					Request: &scanner.ScanRequest{
						Target:     "alpine:3.11",
						ArtifactId: "sha256:e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a",
						BlobIds:    []string{"sha256:5216338b40a7b96416b8b9858974bbe4acc3096ee60acbc4dfb1ee02aecceb10"},
						Options: &scanner.ScanOptions{
							VulnType: []string{"os"},
						},
					},
				},
				Returns: scanReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to detect vulnerabilities via RPC",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockScanner)
			mockClient.ApplyScanExpectation(tt.scanExpectation)

			s := NewScanner(tt.fields.customHeaders, mockClient)
			gotResults, gotOS, gotEosl, err := s.Scan(tt.args.target, tt.args.imageID, tt.args.layerIDs, tt.args.options)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantResults, gotResults)
			assert.Equal(t, tt.wantOS, gotOS)
			assert.Equal(t, tt.wantEosl, gotEosl)
		})
	}
}
