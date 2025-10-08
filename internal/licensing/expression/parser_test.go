package expression

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Expression
		wantStr string
		wantErr string
	}{
		{
			name:  "single license",
			input: "Public Domain",
			want: SimpleExpr{
				License: "Public Domain",
			},
			wantStr: "Public Domain",
		},
		{
			name:  "tag:value license",
			input: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
			want: SimpleExpr{
				License: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
			},
			wantStr: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
		},
		{
			name:  "symbols",
			input: "Public ._-+",
			want: SimpleExpr{
				License: "Public ._-",
				HasPlus: true,
			},
			wantStr: "Public ._-+",
		},
		{
			name:  "multi licenses",
			input: "Public Domain AND ( GPLv2+ or AFL ) AND LGPLv2+ with distribution exceptions",
			want: CompoundExpr{
				left: CompoundExpr{
					left: SimpleExpr{
						License: "Public Domain",
					},
					conjunction: Token{
						token:   AND,
						literal: "AND",
					},
					right: CompoundExpr{
						left: SimpleExpr{
							License: "GPLv2",
							HasPlus: true,
						},
						conjunction: Token{
							token:   OR,
							literal: "or",
						},
						right: SimpleExpr{
							License: "AFL",
						},
					},
				},
				conjunction: Token{
					token:   AND,
					literal: "AND",
				},
				right: CompoundExpr{
					left: SimpleExpr{
						License: "LGPLv2",
						HasPlus: true,
					},
					conjunction: Token{
						token:   WITH,
						literal: "with",
					},
					right: SimpleExpr{
						License: "distribution exceptions",
					},
				},
			},
			wantStr: "Public Domain AND (GPLv2+ or AFL) AND LGPLv2+ with distribution exceptions",
		},
		{
			name:  "nested licenses",
			input: "Public Domain AND ( GPLv2+ or AFL AND ( CC0 or LGPL1.0) )",
			want: CompoundExpr{
				left: SimpleExpr{
					License: "Public Domain",
				},
				conjunction: Token{
					token:   AND,
					literal: "AND",
				},
				right: CompoundExpr{
					left: SimpleExpr{
						License: "GPLv2",
						HasPlus: true,
					},
					conjunction: Token{
						token:   OR,
						literal: "or",
					},
					right: CompoundExpr{
						left: SimpleExpr{
							License: "AFL",
						},
						conjunction: Token{
							token:   AND,
							literal: "AND",
						},
						right: CompoundExpr{
							left: SimpleExpr{
								License: "CC0",
							},
							conjunction: Token{
								token:   OR,
								literal: "or",
							},
							right: SimpleExpr{
								License: "LGPL1.0",
							},
						},
					},
				},
			},
			wantStr: "Public Domain AND (GPLv2+ or AFL AND (CC0 or LGPL1.0))",
		},
		{
			name:    "bad path close bracket not found",
			input:   "Public Domain AND ( GPLv2+ ",
			wantErr: "syntax error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLexer(strings.NewReader(tt.input))
			ret := yyParse(l)
			err := l.Err()
			if tt.wantErr != "" {
				assert.Equal(t, 1, ret)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, l.result)
			assert.Equal(t, tt.wantStr, l.result.String())
		})
	}
}
