package common_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		options  []common.ParseOption
		expected common.PortRange
		valid    bool
	}{
		{
			name:  "single port",
			input: "80",
			expected: common.PortRange{
				Start: iacTypes.IntTest(80),
				End:   iacTypes.IntTest(80),
			},
			valid: true,
		},
		{
			name:  "port range",
			input: "1000-2000",
			expected: common.PortRange{
				Start: iacTypes.IntTest(1000),
				End:   iacTypes.IntTest(2000),
			},
			valid: true,
		},
		{
			name:  "port range with spaces",
			input: " 22 - 80 ",
			expected: common.PortRange{
				Start: iacTypes.IntTest(22),
				End:   iacTypes.IntTest(80),
			},
			valid: true,
		},
		{
			name:    "wildcard allowed",
			input:   "*",
			options: []common.ParseOption{common.WithWildcard()},
			expected: common.PortRange{
				Start: iacTypes.IntTest(0),
				End:   iacTypes.IntTest(65535),
			},
			valid: true,
		},
		{
			name:  "wildcard disallowed",
			input: "*",
			valid: false,
		},
		{
			name:  "invalid string",
			input: "abc",
			valid: false,
		},
		{
			name:  "incomplete range",
			input: "80-",
			valid: false,
		},
		{
			name:  "double dash",
			input: "--",
			valid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta := iacTypes.NewTestMetadata()
			pr := common.ParsePortRange(tc.input, meta, tc.options...)

			if tc.valid {
				assert.True(t, pr.Valid())
				tc.expected.Metadata = meta
				assert.Equal(t, tc.expected, pr)
			} else {
				assert.False(t, pr.Valid())
			}
		})
	}
}
