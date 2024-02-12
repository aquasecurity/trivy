package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SubscriptionResourceID(t *testing.T) {

	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "scope resource id with subscription ID",
			args: []interface{}{
				"4ec875a5-41a2-4837-88cf-4266466e65ed",
				"Microsoft.Authorization/roleDefinitions",
				"8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
				"b34282f6-5e3c-4306-8741-ebd7a871d187",
			},
			expected: "/subscriptions/4ec875a5-41a2-4837-88cf-4266466e65ed/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635/b34282f6-5e3c-4306-8741-ebd7a871d187",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := SubscriptionResourceID(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
