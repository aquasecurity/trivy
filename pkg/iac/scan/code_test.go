package scan

import (
	"os"
	"strings"
	"testing"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/liamg/memoryfs"
)

func TestResult_GetCode(t *testing.T) {

	tests := []struct {
		name       string
		source     string
		filename   string
		start      int
		end        int
		outerStart int
		outerEnd   int
		expected   []Line
		options    []CodeOption
		wantErr    bool
		annotation string
	}{
		{
			name: "basic w/ defaults",
			source: `1
2
3
4`,
			filename: "test.txt",
			start:    2,
			end:      3,
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
			filename:   "main.tf",
			start:      2,
			end:        2,
			outerStart: 1,
			outerEnd:   3,
			options:    []CodeOption{OptionCodeWithHighlighted(false)},
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
			filename: "",
			start:    2,
			end:      3,
			wantErr:  true,
		},
		{
			name: "no line numbers",
			source: `1
2
3
4`,
			filename: "test.txt",
			start:    0,
			end:      0,
			wantErr:  true,
		},
		{
			name: "negative line numbers",
			source: `1
2
3
4`,
			filename: "test.txt",
			start:    -2,
			end:      -1,
			wantErr:  true,
		},
		{
			name: "invalid line numbers",
			source: `1
2
3
4`,
			filename: "test.txt",
			start:    5,
			end:      6,
			wantErr:  true,
		},
		{
			name:     "syntax highlighting",
			source:   `FROM ubuntu`,
			filename: "Dockerfile",
			start:    1,
			end:      1,
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
			name:     "truncation",
			source:   strings.Repeat("If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.\n", 100),
			filename: "longfile.txt",
			start:    1,
			end:      100,
			expected: []Line{
				{
					Number:      1,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  true,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      3,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      4,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      5,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      6,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      7,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      8,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      9,
					Content:     "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					IsCause:     true,
					Highlighted: "If you can do a half-assed job of anything, you're a one-eyed man in a kingdom of the blind.",
					FirstCause:  false,
					LastCause:   true,
				},
				{
					Number:    10,
					Truncated: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := memoryfs.New()
			require.NoError(t, system.WriteFile(test.filename, []byte(test.source), os.ModePerm))
			meta := iacTypes.NewMetadata(
				iacTypes.NewRange(test.filename, test.start, test.end, "", system),
				"",
			)
			if test.outerStart > 0 {
				meta = meta.WithParent(iacTypes.NewMetadata(
					iacTypes.NewRange(test.filename, test.outerStart, test.outerEnd, "", system),
					"",
				))
			}
			result := &Result{
				annotation: test.annotation,
				metadata:   meta,
				fsPath:     test.filename,
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
