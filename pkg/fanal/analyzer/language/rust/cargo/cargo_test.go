package cargo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_cargoAnalyzer_Analyze(t *testing.T) {
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
						Type:     types.Cargo,
						FilePath: "Cargo.lock",
						Packages: types.Packages{
							{
								ID:           "memchr@1.0.2",
								Name:         "memchr",
								Version:      "1.0.2",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   35,
									},
								},
								DependsOn: []string{"libc@0.2.140"},
							},
							{
								ID:           "regex@1.7.3",
								Name:         "regex",
								Version:      "1.7.3",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 43,
										EndLine:   52,
									},
								},
								DependsOn: []string{
									"aho-corasick@0.7.20",
									"memchr@2.5.0",
									"regex-syntax@0.6.29",
								},
							},
							{
								ID:           "regex-syntax@0.5.6",
								Name:         "regex-syntax",
								Version:      "0.5.6",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 54,
										EndLine:   61,
									},
								},
								DependsOn: []string{"ucd-util@0.1.10"},
							},
							{
								ID:           "aho-corasick@0.7.20",
								Name:         "aho-corasick",
								Version:      "0.7.20",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   11,
									},
								},
								DependsOn: []string{"memchr@2.5.0"},
							},
							{
								ID:           "libc@0.2.140",
								Name:         "libc",
								Version:      "0.2.140",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   26,
									},
								},
							},
							{
								ID:           "memchr@2.5.0",
								Name:         "memchr",
								Version:      "2.5.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 37,
										EndLine:   41,
									},
								},
							},
							{
								ID:           "regex-syntax@0.6.29",
								Name:         "regex-syntax",
								Version:      "0.6.29",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 63,
										EndLine:   67,
									},
								},
							},
							{
								ID:           "ucd-util@0.1.10",
								Name:         "ucd-util",
								Version:      "0.1.10",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 69,
										EndLine:   73,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Cargo.toml doesn't include `Dependencies` field",
			dir:  "testdata/toml-only-workspace-deps",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "Cargo.lock",
						Packages: types.Packages{
							{
								ID:           "memchr@2.5.0",
								Name:         "memchr",
								Version:      "2.5.0",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   15,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no Cargo.toml",
			dir:  "testdata/no-cargo-toml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "Cargo.lock",
						Packages: types.Packages{
							{
								ID:           "aho-corasick@0.7.20",
								Name:         "aho-corasick",
								Version:      "0.7.20",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   11,
									},
								},
								DependsOn: []string{"memchr@2.5.0"},
							},
							{
								ID:           "app@0.1.0",
								Name:         "app",
								Version:      "0.1.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 13,
										EndLine:   20,
									},
								},
								DependsOn: []string{
									"memchr@1.0.2",
									"regex-syntax@0.5.6",
									"regex@1.7.3",
								},
							},
							{
								ID:           "libc@0.2.140",
								Name:         "libc",
								Version:      "0.2.140",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   26,
									},
								},
							},
							{
								ID:           "memchr@1.0.2",
								Name:         "memchr",
								Version:      "1.0.2",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   35,
									},
								},
								DependsOn: []string{"libc@0.2.140"},
							},
							{
								ID:           "memchr@2.5.0",
								Name:         "memchr",
								Version:      "2.5.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 37,
										EndLine:   41,
									},
								},
							},
							{
								ID:           "regex@1.7.3",
								Name:         "regex",
								Version:      "1.7.3",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 43,
										EndLine:   52,
									},
								},
								DependsOn: []string{
									"aho-corasick@0.7.20",
									"memchr@2.5.0",
									"regex-syntax@0.6.29",
								},
							},
							{
								ID:           "regex-syntax@0.5.6",
								Name:         "regex-syntax",
								Version:      "0.5.6",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 54,
										EndLine:   61,
									},
								},
								DependsOn: []string{"ucd-util@0.1.10"},
							},
							{
								ID:           "regex-syntax@0.6.29",
								Name:         "regex-syntax",
								Version:      "0.6.29",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 63,
										EndLine:   67,
									},
								},
							},
							{
								ID:           "ucd-util@0.1.10",
								Name:         "ucd-util",
								Version:      "0.1.10",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 69,
										EndLine:   73,
									},
								},
							},
							{
								ID:           "winapi@0.3.9",
								Name:         "winapi",
								Version:      "0.3.9",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 75,
										EndLine:   83,
									},
								},
								DependsOn: []string{
									"winapi-i686-pc-windows-gnu@0.4.0",
									"winapi-x86_64-pc-windows-gnu@0.4.0",
								},
							},
							{
								ID:           "winapi-i686-pc-windows-gnu@0.4.0",
								Name:         "winapi-i686-pc-windows-gnu",
								Version:      "0.4.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 85,
										EndLine:   89,
									},
								},
							},
							{
								ID:           "winapi-x86_64-pc-windows-gnu@0.4.0",
								Name:         "winapi-x86_64-pc-windows-gnu",
								Version:      "0.4.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 91,
										EndLine:   95,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "wrong Cargo.toml",
			dir:  "testdata/wrong-cargo-toml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "Cargo.lock",
						Packages: types.Packages{
							{
								ID:           "app@0.1.0",
								Name:         "app",
								Version:      "0.1.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
								DependsOn: []string{"memchr@2.5.0"},
							},
							{
								ID:           "memchr@2.5.0",
								Name:         "memchr",
								Version:      "2.5.0",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   16,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "broken Cargo.lock",
			dir:  "testdata/sad",
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "workspace members",
			dir:  "testdata/toml-workspace-members",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Cargo,
						FilePath: "Cargo.lock",
						Packages: types.Packages{
							{
								ID:           "gdb-command@0.7.6",
								Name:         "gdb-command",
								Version:      "0.7.6",
								Indirect:     false,
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 14,
										EndLine:   22,
									},
								},
								DependsOn: []string{
									"regex@1.10.2",
									"wait-timeout@0.2.0",
								},
							},
							{
								ID:           "regex@1.10.2",
								Name:         "regex",
								Version:      "1.10.2",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 50,
										EndLine:   60,
									},
								},
								DependsOn: []string{
									"aho-corasick@1.1.2",
									"memchr@2.6.4",
									"regex-automata@0.4.3",
									"regex-syntax@0.8.2",
								},
							},
							{
								ID:           "aho-corasick@1.1.2",
								Name:         "aho-corasick",
								Version:      "1.1.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   12,
									},
								},
								DependsOn: []string{"memchr@2.6.4"},
							},
							{
								ID:           "libc@0.2.150",
								Name:         "libc",
								Version:      "0.2.150",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 24,
										EndLine:   28,
									},
								},
							},
							{
								ID:           "memchr@2.6.4",
								Name:         "memchr",
								Version:      "2.6.4",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 44,
										EndLine:   48,
									},
								},
							},
							{
								ID:           "regex-automata@0.4.3",
								Name:         "regex-automata",
								Version:      "0.4.3",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 62,
										EndLine:   71,
									},
								},
								DependsOn: []string{
									"aho-corasick@1.1.2",
									"memchr@2.6.4",
									"regex-syntax@0.8.2",
								},
							},
							{
								ID:           "regex-syntax@0.8.2",
								Name:         "regex-syntax",
								Version:      "0.8.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 73,
										EndLine:   77,
									},
								},
							},
							{
								ID:           "wait-timeout@0.2.0",
								Name:         "wait-timeout",
								Version:      "0.2.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 79,
										EndLine:   86,
									},
								},
								DependsOn: []string{"libc@0.2.150"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newCargoAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string // version from Cargo.lock
		constraint string // version from Cargo.toml
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
			a := cargoAnalyzer{
				comparer: compare.GenericComparer{},
			}
			match, _ := a.matchVersion(tt.version, tt.constraint)
			assert.Equal(t, tt.want, match)
		})
	}
}
