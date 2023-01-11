package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/licensing/expression/lexer"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		normFunc  []NormalizeFunc
		expect    *LicenseExpression
		expectStr string
		expectErr string
	}{
		{
			name:  "happy path single license",
			input: "Public Domain",
			expect: &LicenseExpression{
				Node: Node{
					License: "Public Domain",
				},
			},
			expectStr: "Public Domain",
		},
		{
			name:  "happy path tag:value license",
			input: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
			expect: &LicenseExpression{
				Node: Node{
					License: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
				},
			},
			expectStr: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
		},
		{
			name:  "happy path single license with norm func",
			input: "Public Domain with exception",
			expect: &LicenseExpression{
				Node: Node{
					License: "Public Domain with exception",
				},
			},
			normFunc: []NormalizeFunc{
				func(n string) string {
					return strings.Replace(n, " ", "_", -1)
				},
				func(n string) string {
					if n == "Public_Domain_with_exception" {
						return "Unlicense"
					}
					return n
				},
			},
			expectStr: "Unlicense",
		},
		{
			name:  "happy path 2",
			input: "Public ._+-",
			expect: &LicenseExpression{
				Node: Node{
					License: "Public ._+-",
				},
			},
			expectStr: "Public ._+-",
		},
		{
			name:  "happy path multi license",
			input: "Public Domain AND ( GPLv2+ or AFL ) AND LGPLv2+ with distribution exceptions",
			expect: &LicenseExpression{
				Node: Node{
					License: "Public Domain",
				},
				Operator: "AND",
				Next: &LicenseExpression{
					Node: Node{
						LicenseExpression: &LicenseExpression{
							Node: Node{
								License: "GPLv2+",
							},
							Operator: "OR",
							Next: &LicenseExpression{
								Node: Node{
									License: "AFL",
								},
							},
						},
					},
					Operator: "AND",
					Next: &LicenseExpression{
						Node: Node{
							License: "LGPLv2+ with distribution exceptions",
						},
					},
				},
			},
			expectStr: "Public Domain AND ( GPLv2+ OR AFL ) AND LGPLv2+ with distribution exceptions",
		},
		{
			name:  "happy path nested license",
			input: "Public Domain AND ( GPLv2+ or AFL AND ( CC0 or LGPL1.0) )",
			expect: &LicenseExpression{
				Node: Node{
					License: "Public Domain",
				},
				Operator: "AND",
				Next: &LicenseExpression{
					Node: Node{
						LicenseExpression: &LicenseExpression{
							Node: Node{
								License: "GPLv2+",
							},
							Operator: "OR",
							Next: &LicenseExpression{
								Node: Node{
									License: "AFL",
								},
								Operator: "AND",
								Next: &LicenseExpression{
									Node: Node{
										LicenseExpression: &LicenseExpression{
											Node: Node{
												License: "CC0",
											},
											Operator: "OR",
											Next: &LicenseExpression{
												Node: Node{
													License: "LGPL1.0",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectStr: "Public Domain AND ( GPLv2+ OR AFL AND ( CC0 OR LGPL1.0 ) )",
		},
		{
			name:  "happy path 2",
			input: "( GPLv2+ or CC0 )",
			expect: &LicenseExpression{
				Node: Node{
					LicenseExpression: &LicenseExpression{
						Node: Node{
							License: "GPLv2+",
						},
						Operator: "OR",
						Next: &LicenseExpression{
							Node: Node{
								License: "CC0",
							},
						},
					},
				},
			},
			expectStr: "( GPLv2+ OR CC0 )",
		},
		{
			name:      "bad path close bracket not found",
			input:     "Public Domain AND ( GPLv2+ ",
			expectErr: "invalid expression error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := lexer.New(tt.input)
			p := New(l).RegisterNormalizeFunc(tt.normFunc...)

			got, err := p.Parse()
			if tt.expectErr != "" {
				assert.Equal(t, err.Error(), tt.expectErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expect, got)
			assert.Equal(t, tt.expectStr, p.Normalize(got))
		})
	}
}
