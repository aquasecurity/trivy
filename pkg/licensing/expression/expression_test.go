package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeForSPDX(t *testing.T) {
	tests := []struct {
		name    string
		license string
		want    string
	}{
		{
			name:    "happy path",
			license: "AFL 2.0",
			want:    "AFL-2.0",
		},
		{
			name:    "happy path with WITH section",
			license: "AFL 2.0 with Linux-syscall-note exception",
			want:    "AFL-2.0 WITH Linux-syscall-note-exception",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NormalizeForSPDX(tt.license), "NormalizeWithExpression(%v)", tt.license)
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		name          string
		inputElements []string
		inputOperator Operator
		expect        string
	}{
		{
			name:          "happy path single license",
			inputElements: []string{"MIT"},
			inputOperator: AND,
			expect:        "MIT",
		},
		{
			name:          "happy path multi license",
			inputElements: []string{"MIT", "GPL1.0"},
			inputOperator: AND,
			expect:        "MIT AND GPL1.0",
		},
		{
			name:          "happy path multi license with AND operator",
			inputElements: []string{"MIT", "GPL1.0 AND GPL2.0"},
			inputOperator: AND,
			expect:        "MIT AND GPL1.0 AND GPL2.0",
		},
		{
			name:          "happy path multi license with OR operator",
			inputElements: []string{"MIT", "GPL1.0 OR GPL2.0"},
			inputOperator: OR,
			expect:        "MIT OR GPL1.0 OR GPL2.0",
		},
		{
			name:          "happy path multi license with OR operator, separator AND",
			inputElements: []string{"MIT", "GPL1.0 OR GPL2.0"},
			inputOperator: AND,
			expect:        "MIT AND (GPL1.0 OR GPL2.0)",
		},
		{
			name:          "happy path multi license with AND operator, separator OR",
			inputElements: []string{"MIT", "GPL1.0 AND GPL2.0"},
			inputOperator: OR,
			expect:        "MIT OR (GPL1.0 AND GPL2.0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Join(tt.inputElements, tt.inputOperator)
			assert.Equal(t, tt.expect, got)
		})
	}
}
