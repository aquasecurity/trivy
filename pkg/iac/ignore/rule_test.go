package ignore_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func metadataWithLine(path string, line int) types.Metadata {
	return types.NewMetadata(types.NewRange(path, line, line, "", nil), "")
}

func TestRules_Ignore(t *testing.T) {

	const filename = "test"

	type args struct {
		metadata types.Metadata
		ids      []string
	}

	tests := []struct {
		name         string
		src          string
		args         args
		shouldIgnore bool
	}{
		{
			name:         "no ignore",
			src:          `#test`,
			shouldIgnore: false,
		},
		{
			name: "one ignore rule",
			src:  `#trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "blank line between rule and finding",
			src:  `#trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 3),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: false,
		},
		{
			name: "blank line between rules",
			src: `#trivy:ignore:rule-1

#trivy:ignore:rule-2	
`,
			args: args{
				metadata: metadataWithLine(filename, 4),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: false,
		},
		{
			name: "rule and a finding on the same line",
			src:  `#trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 1),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "rule and a finding on the same line",
			src:  `test #trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 1),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "multiple rules on one line",
			src:  `test #trivy:ignore:rule-1 #trivy:ignore:rule-2`,
			args: args{
				metadata: metadataWithLine(filename, 1),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: true,
		},
		{
			name: "rule and find from different files",
			src:  `test #trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine("another-file", 1),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: false,
		},
		{
			name: "multiple ignore rule",
			src: `#trivy:ignore:rule-1
#trivy:ignore:rule-2
`,
			args: args{
				metadata: metadataWithLine(filename, 3),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "ignore section with params",
			src:  `#trivy:ignore:rule-1[param1=1]`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "id's don't match",
			src:  `#trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: false,
		},
		{
			name: "without ignore section",
			src:  `#trivy:exp:2022-01-01`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: false,
		},
		{
			name: "non valid ignore section",
			src:  `#trivy:ignore`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: false,
		},
		{
			name: "ignore rule with expiry date passed",
			src:  `#trivy:ignore:rule-1:exp:2022-01-01`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: false,
		},
		{
			name: "ignore rule with expiry date not passed",
			src:  `#trivy:ignore:rule-1:exp:2026-01-01`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "ignore rule with invalid expiry date",
			src:  `#trivy:ignore:rule-1:exp:2026-99-01`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: false,
		},
		{
			name: "with valid wildcard",
			src:  `#trivy:ignore:rule-*`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "with non-valid wildcard",
			src:  `#trivy:ignore:rule-1-*d`,
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1-abc"},
			},
			shouldIgnore: false,
		},
		{
			name: "multiple ignore rules on the same line",
			src: `test #trivy:ignore:rule-1
test #trivy:ignore:rule-2
		`,
			args: args{
				metadata: metadataWithLine(filename, 1),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "multiple ignore rules on the same line",
			src: `# trivy:ignore:rule-1
# trivy:ignore:rule-2
test #trivy:ignore:rule-3
`,
			args: args{
				metadata: metadataWithLine(filename, 3),
				ids:      []string{"rule-1"},
			},
			shouldIgnore: true,
		},
		{
			name: "multiple ignore rules on the same line",
			src: `# trivy:ignore:rule-1 # trivy:ignore:rule-2
# trivy:ignore:rule-3
test #trivy:ignore:rule-4
`,
			args: args{
				metadata: metadataWithLine(filename, 3),
				ids:      []string{"rule-2"},
			},
			shouldIgnore: true,
		},
		{
			name: "multiple ids",
			src:  `# trivy:ignore:rule-1`,
			args: args{
				metadata: metadataWithLine(filename, 1),
				ids:      []string{"rule-1", "rule-2"},
			},
			shouldIgnore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := ignore.Parse(tt.src, "", filename)
			got := rules.Ignore(tt.args.metadata, tt.args.ids, nil)
			assert.Equal(t, tt.shouldIgnore, got)
		})
	}
}

func TestRules_IgnoreWithCustomIgnorer(t *testing.T) {
	const filename = "test"

	type args struct {
		metadata types.Metadata
		ids      []string
		ignorers map[string]ignore.Ignorer
	}

	tests := []struct {
		name         string
		src          string
		parser       ignore.RuleSectionParser
		args         args
		shouldIgnore bool
	}{
		{
			name: "happy",
			src:  `#trivy:ignore:rule-1:ws:dev`,
			parser: &ignore.StringMatchParser{
				SectionKey: "ws",
			},
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
				ignorers: map[string]ignore.Ignorer{
					"ws": func(_ types.Metadata, param any) bool {
						ws, ok := param.(string)
						if !ok {
							return false
						}
						return ws == "dev"
					},
				},
			},
			shouldIgnore: true,
		},
		{
			name: "with wildcard",
			src:  `#trivy:ignore:rule-1:ws:dev-*`,
			parser: &ignore.StringMatchParser{
				SectionKey: "ws",
			},
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
				ignorers: map[string]ignore.Ignorer{
					"ws": func(_ types.Metadata, param any) bool {
						ws, ok := param.(string)
						if !ok {
							return false
						}
						return ignore.MatchPattern("dev-stage1", ws)
					},
				},
			},
			shouldIgnore: true,
		},
		{
			name: "bad",
			src:  `#trivy:ignore:rule-1:ws:prod`,
			parser: &ignore.StringMatchParser{
				SectionKey: "ws",
			},
			args: args{
				metadata: metadataWithLine(filename, 2),
				ids:      []string{"rule-1"},
				ignorers: map[string]ignore.Ignorer{
					"ws": func(_ types.Metadata, param any) bool {
						ws, ok := param.(string)
						if !ok {
							return false
						}
						return ws == "dev"
					},
				},
			},
			shouldIgnore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := ignore.Parse(tt.src, filename, "", tt.parser)
			got := rules.Ignore(tt.args.metadata, tt.args.ids, tt.args.ignorers)
			assert.Equal(t, tt.shouldIgnore, got)
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		input    string
		pattern  string
		expected bool
	}{
		{"foo-test-bar", "*-test-*", true},
		{"foo-test-bar", "*-example-*", false},
		{"test", "*test", true},
		{"example", "test", false},
		{"example-test", "*-test*", true},
		{"example-test", "*example-*", true},
	}

	for _, tc := range tests {
		t.Run(tc.input+":"+tc.pattern, func(t *testing.T) {
			got := ignore.MatchPattern(tc.input, tc.pattern)
			assert.Equal(t, tc.expected, got)
		})
	}
}
