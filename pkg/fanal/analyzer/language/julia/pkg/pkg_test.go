package julia

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
						Libraries: []types.Package{
							{
								ID:        "ade2ca70-3891-5945-98fb-dc099432e06a",
								Name:      "Dates",
								Version:   "1.9.0",
								Indirect:  false,
								Locations: []types.Location{{StartLine: 7, EndLine: 9}},
								DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newJuliaAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string // version from Julia.lock
		constraint string // version from Julia.toml
		want       bool
	}{
		{
			name:       "major version == 0.",
			version:    "0.0.4",
			constraint: "0.0.3",
			want:       false,
		},
		{
			name:       "major version > 0.",
			version:    "1.2.4",
			constraint: "1.2.3",
			want:       true,
		},
		{
			name:       "Caret prefix",
			version:    "1.5.0",
			constraint: "^1.2",
			want:       true,
		},
		{
			name:       "Tilde prefix. Minor version",
			version:    "1.3.4",
			constraint: "~ 1.2",
			want:       false,
		},
		{
			name:       "Tilde prefix. Patch version",
			version:    "1.2.4",
			constraint: "~ 1.2.3",
			want:       true,
		},
		{
			name:       "Comparison prefix",
			version:    "2.5.0",
			constraint: "< 2.5.0",
			want:       false,
		},
		{
			name:       "Multiple prefixes",
			version:    "2.5.0",
			constraint: ">= 2.5, < 2.5.1",
			want:       true,
		},
		{
			name:       "= prefix",
			version:    "2.5.0",
			constraint: "= 2.5",
			want:       true,
		},
		{
			name:       "`*` constraint",
			version:    "2.5.0",
			constraint: "*",
			want:       true,
		},
		{
			name:       "constraint with `.*`",
			version:    "2.5.0",
			constraint: "2.5.*",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := juliaAnalyzer{
				comparer: compare.GenericComparer{},
			}
			match, _ := a.matchVersion(tt.version, tt.constraint)
			assert.Equal(t, tt.want, match)
		})
	}
}
