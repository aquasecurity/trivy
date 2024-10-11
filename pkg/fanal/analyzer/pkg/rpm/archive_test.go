package rpm

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_rpmArchiveAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    *analyzer.AnalysisResult
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "valid",
			input: analyzer.AnalysisInput{
				FilePath: "testdata/valid.rpm",
				Content:  lo.Must(os.Open("testdata/socat-1.7.3.2-2.el7.x86_64.rpm")), // Must run 'mage rpm:fixtures' before this test
			},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "testdata/valid.rpm",
						Packages: types.Packages{
							{
								Name:       "socat",
								Version:    "1.7.3.2",
								Release:    "2.el7",
								Arch:       "x86_64",
								SrcName:    "socat",
								SrcVersion: "1.7.3.2",
								SrcRelease: "2.el7",
								FilePath:   "testdata/valid.rpm",
								Licenses: []string{
									"GPLv2",
								},
								Maintainer: "Red Hat, Inc.",
								Identifier: types.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeRPM,
										Namespace: "redhat",
										Name:      "socat",
										Version:   "1.7.3.2-2.el7",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "arch",
												Value: "x86_64",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name: "broken",
			input: analyzer.AnalysisInput{
				FilePath: "testdata/broken.rpm",
				Content:  strings.NewReader(`broken`),
			},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newRPMArchiveAnalyzer()
			got, err := a.Analyze(context.Background(), tt.input)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
