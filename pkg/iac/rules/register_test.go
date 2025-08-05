package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func Test_Reset(t *testing.T) {
	Reset()
	rule := scan.Rule{}
	_ = Register(rule)
	assert.Len(t, GetFrameworkRules(), 1)
	Reset()
	assert.Empty(t, GetFrameworkRules())
}

func Test_Registration(t *testing.T) {
	var tests = []struct {
		name                 string
		registeredFrameworks map[framework.Framework][]string
		inputFrameworks      []framework.Framework
		expected             bool
	}{
		{
			name:     "rule without framework specified should be returned when no frameworks are requested",
			expected: true,
		},
		{
			name:            "rule without framework specified should not be returned when a specific framework is requested",
			inputFrameworks: []framework.Framework{framework.CIS_AWS_1_2},
			expected:        false,
		},
		{
			name:            "rule without framework specified should be returned when the default framework is requested",
			inputFrameworks: []framework.Framework{framework.Default},
			expected:        true,
		},
		{
			name:                 "rule with default framework specified should be returned when the default framework is requested",
			registeredFrameworks: map[framework.Framework][]string{framework.Default: {"1.1"}},
			inputFrameworks:      []framework.Framework{framework.Default},
			expected:             true,
		},
		{
			name:                 "rule with default framework specified should not be returned when a specific framework is requested",
			registeredFrameworks: map[framework.Framework][]string{framework.Default: {"1.1"}},
			inputFrameworks:      []framework.Framework{framework.CIS_AWS_1_2},
			expected:             false,
		},
		{
			name:                 "rule with specific framework specified should not be returned when a default framework is requested",
			registeredFrameworks: map[framework.Framework][]string{framework.CIS_AWS_1_2: {"1.1"}},
			inputFrameworks:      []framework.Framework{framework.Default},
			expected:             false,
		},
		{
			name:                 "rule with specific framework specified should be returned when the specific framework is requested",
			registeredFrameworks: map[framework.Framework][]string{framework.CIS_AWS_1_2: {"1.1"}},
			inputFrameworks:      []framework.Framework{framework.CIS_AWS_1_2},
			expected:             true,
		},
		{
			name:                 "rule with multiple frameworks specified should be returned when the specific framework is requested",
			registeredFrameworks: map[framework.Framework][]string{framework.CIS_AWS_1_2: {"1.1"}, "blah": {"1.2"}},
			inputFrameworks:      []framework.Framework{framework.CIS_AWS_1_2},
			expected:             true,
		},
		{
			name:                 "rule with multiple frameworks specified should be returned only once when multiple matching frameworks are requested",
			registeredFrameworks: map[framework.Framework][]string{framework.CIS_AWS_1_2: {"1.1"}, "blah": {"1.2"}, "something": {"1.3"}},
			inputFrameworks:      []framework.Framework{framework.CIS_AWS_1_2, "blah", "other"},
			expected:             true,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Reset()
			rule := scan.Rule{
				ID:         fmt.Sprintf("%d-%s", i, test.name),
				Frameworks: test.registeredFrameworks,
			}
			_ = Register(rule)
			var found bool
			for _, matchedRule := range GetFrameworkRules(test.inputFrameworks...) {
				if matchedRule.GetRule().ID == rule.ID {
					assert.False(t, found, "rule should not be returned more than once")
					found = true
				}
			}
			assert.Equal(t, test.expected, found, "rule should be returned if it matches any of the input frameworks")
		})
	}
}

func Test_Deregistration(t *testing.T) {
	Reset()
	registrationA := Register(scan.Rule{
		ID: "A",
	})
	registrationB := Register(scan.Rule{
		ID: "B",
	})
	assert.Len(t, GetFrameworkRules(), 2)
	Deregister(registrationA)
	actual := GetFrameworkRules()
	require.Len(t, actual, 1)
	assert.Equal(t, "B", actual[0].GetRule().ID)
	Deregister(registrationB)
	assert.Empty(t, GetFrameworkRules())
}

func Test_DeregistrationMultipleFrameworks(t *testing.T) {
	Reset()
	registrationA := Register(scan.Rule{
		ID: "A",
	})
	registrationB := Register(scan.Rule{
		ID: "B",
		Frameworks: map[framework.Framework][]string{
			"a":               nil,
			"b":               nil,
			"c":               nil,
			framework.Default: nil,
		},
	})
	assert.Len(t, GetFrameworkRules(), 2)
	Deregister(registrationA)
	actual := GetFrameworkRules()
	require.Len(t, actual, 1)
	assert.Equal(t, "B", actual[0].GetRule().ID)
	Deregister(registrationB)
	assert.Empty(t, GetFrameworkRules())
}
