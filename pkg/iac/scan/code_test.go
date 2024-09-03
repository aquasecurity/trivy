package scan

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestResult_GetCode(t *testing.T) {
	const line = "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind."
	tests := []struct {
		name           string
		source         string
		filename       string
		startInnerLine int
		endInnerLine   int
		startOuterLine int
		endOuterLine   int
		expected       []Line
		options        []CodeOption
		wantErr        bool
	}{
		{
			name: "basic w/ defaults",
			source: `1
2
3
4`,
			filename:       "test.txt",
			startInnerLine: 2,
			endInnerLine:   3,
			expected: []Line{
				{
					Number:      2,
					Content:     "2",
					IsCause:     true,
					Highlighted: "2",
					FirstCause:  true,
					LastCause:   false,
				},
				{
					Number:      3,
					Content:     "3",
					IsCause:     true,
					Highlighted: "3",
					FirstCause:  false,
					LastCause:   true,
				},
			},
		},
		{
			name: "nested ranges",
			source: `resource "aws_s3_bucket" "something" {
	bucket = "something"
}`,
			filename:       "main.tf",
			startInnerLine: 2,
			endInnerLine:   2,
			startOuterLine: 1,
			endOuterLine:   3,
			options:        []CodeOption{OptionCodeWithHighlighted(false)},
			expected: []Line{
				{
					Number:  1,
					Content: `resource "aws_s3_bucket" "something" {`,
				},
				{
					Number:     2,
					Content:    `	bucket = "something"`,
					IsCause:    true,
					FirstCause: true,
					LastCause:  true,
				},
				{
					Number:  3,
					Content: "}",
				},
			},
		},
		{
			name: "bad filename",
			source: `1
2
3
4`,
			filename:       "",
			startInnerLine: 2,
			endInnerLine:   3,
			wantErr:        true,
		},
		{
			name: "no line numbers",
			source: `1
2
3
4`,
			filename:       "test.txt",
			startInnerLine: 0,
			endInnerLine:   0,
			wantErr:        true,
		},
		{
			name: "negative line numbers",
			source: `1
2
3
4`,
			filename:       "test.txt",
			startInnerLine: -2,
			endInnerLine:   -1,
			wantErr:        true,
		},
		{
			name: "invalid line numbers",
			source: `1
2
3
4`,
			filename:       "test.txt",
			startInnerLine: 5,
			endInnerLine:   6,
			wantErr:        true,
		},
		{
			name:           "syntax highlighting",
			source:         `FROM ubuntu`,
			filename:       "Dockerfile",
			startInnerLine: 1,
			endInnerLine:   1,
			expected: []Line{
				{
					Number:      1,
					Content:     "FROM ubuntu",
					IsCause:     true,
					Highlighted: "\x1b[38;5;64mFROM\x1b[0m\x1b[38;5;37m ubuntu\x1b[0m",
					FirstCause:  true,
					LastCause:   true,
				},
			},
		},
		{
			name:           "truncation",
			source:         strings.Repeat(line+"\n", 100),
			filename:       "longfile.txt",
			startInnerLine: 1,
			endInnerLine:   100,
			expected: []Line{
				{
					Number:      1,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  true,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      3,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      4,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      5,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      6,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      7,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      8,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      9,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
					FirstCause:  false,
					LastCause:   true,
				},
				{
					Number:    10,
					Truncated: true,
				},
			},
		},
		{
			name:           "invalid inner range",
			source:         `Test`,
			filename:       "test.txt",
			startInnerLine: 0,
			endInnerLine:   0,
			wantErr:        true,
		},
		{
			name:           "invalid outer range",
			source:         `Test`,
			filename:       "test.txt",
			startInnerLine: 10,
			endInnerLine:   12,
			startOuterLine: 5,
			endOuterLine:   3,
			wantErr:        true,
		},
		{
			name:           "truncate with outer range",
			source:         strings.Repeat(line+"\n", 100),
			filename:       "longfile.txt",
			startOuterLine: 1,
			endOuterLine:   100,
			startInnerLine: 10,
			endInnerLine:   12,
			options:        []CodeOption{OptionCodeWithTruncation(true)},
			expected: []Line{
				{
					Number:      1,
					Content:     line,
					Highlighted: line,
				},
				{
					Number:    2,
					Truncated: true,
				},
				{
					Number:      10,
					Content:     line,
					IsCause:     true,
					FirstCause:  true,
					Highlighted: line,
				},
				{
					Number:      11,
					Content:     line,
					IsCause:     true,
					Highlighted: line,
				},
				{
					Number:      12,
					Content:     line,
					IsCause:     true,
					LastCause:   true,
					Highlighted: line,
				},
				{
					Number:    99,
					Truncated: true,
				},
				{
					Number:      100,
					Content:     line,
					Highlighted: line,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				test.filename: &fstest.MapFile{
					Data: []byte(test.source),
				},
			}

			meta := iacTypes.NewMetadata(
				iacTypes.NewRange(test.filename, test.startInnerLine, test.endInnerLine, "", fsys),
				"",
			)
			if test.startOuterLine > 0 {
				meta = meta.WithParent(iacTypes.NewMetadata(
					iacTypes.NewRange(test.filename, test.startOuterLine, test.endOuterLine, "", fsys),
					"",
				))
			}
			result := &Result{
				metadata: meta,
				fsPath:   test.filename,
			}
			code, err := result.GetCode(test.options...)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, code.Lines)
		})
	}

}

func TestCode_IsCauseMultiline(t *testing.T) {

	tests := []struct {
		name     string
		code     Code
		expected bool
	}{
		{
			name: "no cause",
			code: Code{
				Lines: []Line{
					{
						Number:      1,
						Content:     "Test",
						Highlighted: "Test",
					},
				},
			},
			expected: false,
		},
		{
			name: "one cause",
			code: Code{
				Lines: []Line{
					{
						Number:      1,
						Content:     "Test",
						IsCause:     true,
						Highlighted: "Test",
					},
				},
			},
			expected: false,
		},
		{
			name: "multiple causes",
			code: Code{
				Lines: []Line{
					{
						Number:      1,
						Content:     "Test",
						IsCause:     true,
						Highlighted: "Test",
					},
					{
						Number:      2,
						Content:     "Test",
						IsCause:     true,
						Highlighted: "Test",
					},
					{
						Number:      3,
						Content:     "Test",
						IsCause:     true,
						Highlighted: "Test",
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.IsCauseMultiline())
		})
	}
}
