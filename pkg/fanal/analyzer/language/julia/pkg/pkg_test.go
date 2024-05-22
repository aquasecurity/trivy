package pkgjl

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_juliaAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Julia,
						FilePath: "Manifest.toml",
						Packages: types.Packages{
							{
								ID:        "ade2ca70-3891-5945-98fb-dc099432e06a",
								Name:      "Dates",
								Version:   "1.9.0",
								Indirect:  false,
								Locations: []types.Location{{StartLine: 7, EndLine: 9}},
								DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7"},
							},
							{
								ID:        "d9a60922-03b4-4a1b-81be-b8d05b827236",
								Name:      "DevDep",
								Version:   "1.0.0",
								Indirect:  false,
								Dev:       true,
								Locations: []types.Location{{StartLine: 65, EndLine: 68}},
								DependsOn: []string{"b637660b-5035-4894-8335-b3805a4b50d8"},
							},
							{
								ID:        "b637660b-5035-4894-8335-b3805a4b50d8",
								Name:      "IndirectDevDep",
								Version:   "2.0.0",
								Indirect:  true,
								Dev:       true,
								Locations: []types.Location{{StartLine: 70, EndLine: 72}},
							},
							{
								ID:        "682c06a0-de6a-54ab-a142-c8b1cf79cde6",
								Name:      "JSON",
								Version:   "0.21.4",
								Indirect:  false,
								Locations: []types.Location{{StartLine: 11, EndLine: 15}},
								DependsOn: []string{
									"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5",
									"69de0a69-1ddd-5017-9359-2bf0b02dc9f0",
									"a63ad114-7e13-5084-954f-fe012c677804",
									"ade2ca70-3891-5945-98fb-dc099432e06a",
								},
							},
							{
								ID:        "a63ad114-7e13-5084-954f-fe012c677804",
								Name:      "Mmap",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 17, EndLine: 18}},
							},
							{
								ID:        "69de0a69-1ddd-5017-9359-2bf0b02dc9f0",
								Name:      "Parsers",
								Version:   "2.5.10",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 20, EndLine: 24}},
								DependsOn: []string{
									"ade2ca70-3891-5945-98fb-dc099432e06a",
									"aea7be01-6a6a-4083-8856-8a6e6704d82a",
									"cf7118a7-6976-5b1a-9a39-7adc72f591a4",
								},
							},
							{
								ID:        "aea7be01-6a6a-4083-8856-8a6e6704d82a",
								Name:      "PrecompileTools",
								Version:   "1.1.1",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 26, EndLine: 30}},
								DependsOn: []string{"21216c6a-2e73-6563-6e65-726566657250"},
							},
							{
								ID:        "21216c6a-2e73-6563-6e65-726566657250",
								Name:      "Preferences",
								Version:   "1.4.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 32, EndLine: 36}},
								DependsOn: []string{"fa267f1f-6049-4f14-aa54-33bafae1ed76"},
							},
							{
								ID:        "de0858da-6303-5e67-8744-51eddeeeb8d7",
								Name:      "Printf",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 38, EndLine: 40}},
								DependsOn: []string{"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"},
							},
							{
								ID:        "9a3f8284-a2c9-5f02-9a11-845980a1fd5c",
								Name:      "Random",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 42, EndLine: 44}},
								DependsOn: []string{"9e88b42a-f829-5b0c-bbe9-9e923198166b", "ea8e919c-243c-51af-8825-aaa63cd721ce"},
							},
							{
								ID:        "ea8e919c-243c-51af-8825-aaa63cd721ce",
								Name:      "SHA",
								Version:   "0.7.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 46, EndLine: 48}},
							},
							{
								ID:        "9e88b42a-f829-5b0c-bbe9-9e923198166b",
								Name:      "Serialization",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 50, EndLine: 51}},
							},
							{
								ID:        "fa267f1f-6049-4f14-aa54-33bafae1ed76",
								Name:      "TOML",
								Version:   "1.0.3",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 53, EndLine: 56}},
								DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a"},
							},
							{
								ID:        "cf7118a7-6976-5b1a-9a39-7adc72f591a4",
								Name:      "UUIDs",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 58, EndLine: 60}},
								DependsOn: []string{"9a3f8284-a2c9-5f02-9a11-845980a1fd5c", "ea8e919c-243c-51af-8825-aaa63cd721ce"},
							},
							{
								ID:        "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5",
								Name:      "Unicode",
								Version:   "1.9.0",
								Indirect:  true,
								Locations: []types.Location{{StartLine: 62, EndLine: 63}},
							},
						},
					},
				},
			},
		},
		{
			name: "no_deps_v1.6",
			dir:  "testdata/no_deps_v1.6",
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "dep_ext_v1.9",
			dir:  "testdata/dep_ext_v1.9",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Julia,
						FilePath: "Manifest.toml",
						Packages: types.Packages{
							{
								ID:        "621f4979-c628-5d54-868e-fcf4e3e8185c",
								Name:      "AbstractFFTs",
								Version:   "1.3.1",
								Indirect:  false,
								Locations: []types.Location{{StartLine: 7, EndLine: 10}},
								DependsOn: nil,
							},
						},
					},
				},
			},
		},
		{
			name: "no_manifest",
			dir:  "testdata/no_manifest",
			want: &analyzer.AnalysisResult{
				Applications: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newJuliaAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
