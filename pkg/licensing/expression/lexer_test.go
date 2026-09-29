package expression

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLexer_Lex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []Token
	}{
		{
			name:  "simple",
			input: "GPL-2.0-only",
			want: []Token{
				{
					token:   IDENT,
					literal: "GPL-2.0-only",
				},
			},
		},
		{
			name:  "with space",
			input: "Public Domain",
			want: []Token{
				{
					token:   IDENT,
					literal: "Public",
				},
				{
					token:   IDENT,
					literal: "Domain",
				},
			},
		},
		{
			name:  "and",
			input: "Public Domain AND MIT",
			want: []Token{
				{
					token:   IDENT,
					literal: "Public",
				},
				{
					token:   IDENT,
					literal: "Domain",
				},
				{
					token:   AND,
					literal: "AND",
				},
				{
					token:   IDENT,
					literal: "MIT",
				},
			},
		},
		{
			name:  "or",
			input: "LGPL-2.1-only OR MIT OR BSD-3-Clause",
			want: []Token{
				{
					token:   IDENT,
					literal: "LGPL-2.1-only",
				},
				{
					token:   OR,
					literal: "OR",
				},
				{
					token:   IDENT,
					literal: "MIT",
				},
				{
					token:   OR,
					literal: "OR",
				},
				{
					token:   IDENT,
					literal: "BSD-3-Clause",
				},
			},
		},
		{
			name:  "parenthesis",
			input: "LGPL-2.1-only AND (MIT OR BSD-3-Clause)",
			want: []Token{
				{
					token:   IDENT,
					literal: "LGPL-2.1-only",
				},
				{
					token:   AND,
					literal: "AND",
				},
				{
					token:   int('('),
					literal: "(",
				},
				{
					token:   IDENT,
					literal: "MIT",
				},
				{
					token:   OR,
					literal: "OR",
				},
				{
					token:   IDENT,
					literal: "BSD-3-Clause",
				},
				{
					token:   int(')'),
					literal: ")",
				},
			},
		},
		{
			name:  "exception",
			input: "LGPL-2.1-only AND GPL-2.0-or-later WITH Bison-exception-2.2",
			want: []Token{
				{
					token:   IDENT,
					literal: "LGPL-2.1-only",
				},
				{
					token:   AND,
					literal: "AND",
				},
				{
					token:   IDENT,
					literal: "GPL-2.0-or-later",
				},
				{
					token:   WITH,
					literal: "WITH",
				},
				{
					token:   IDENT,
					literal: "Bison-exception-2.2",
				},
			},
		},
		{
			name:  "plus",
			input: "Public Domain+",
			want: []Token{
				{
					token:   IDENT,
					literal: "Public",
				},
				{
					token:   IDENT,
					literal: "Domain",
				},
				{
					token:   int('+'),
					literal: "+",
				},
			},
		},
		{
			name:  "plus in the middle",
			input: "ISC+IBM",
			want: []Token{
				{
					token:   IDENT,
					literal: "ISC+IBM",
				},
			},
		},
		{
			name:  "plus with the parenthesis",
			input: "(GPL1.0+)",
			want: []Token{
				{
					token:   int('('),
					literal: "(",
				},
				{
					token:   IDENT,
					literal: "GPL1.0",
				},
				{
					token:   int('+'),
					literal: "+",
				},
				{
					token:   int(')'),
					literal: ")",
				},
			},
		},
		{
			name:  "utf-8",
			input: "GPL1.0+ " + string(byte(0x20)) + "あ🇯🇵" + " and LGPL1.0",
			want: []Token{
				{
					token:   IDENT,
					literal: "GPL1.0",
				},
				{
					token:   int('+'),
					literal: "+",
				},
				{
					token:   IDENT,
					literal: "あ🇯🇵",
				},
				{
					token:   AND,
					literal: "and",
				},
				{
					token:   IDENT,
					literal: "LGPL1.0",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLexer(strings.NewReader(tt.input))
			var got []Token
			var lval yySymType
			for l.Lex(&lval) != 0 {
				got = append(got, lval.token)
				lval = yySymType{}
			}
			require.NoError(t, l.Err())
			assert.Equal(t, tt.want, got)
		})
	}
}
