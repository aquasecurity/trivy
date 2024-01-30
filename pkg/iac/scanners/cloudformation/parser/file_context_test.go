package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileContext_OverrideParameters(t *testing.T) {
	tests := []struct {
		name     string
		ctx      FileContext
		arg      map[string]any
		expected map[string]*Parameter
	}{
		{
			name: "happy",
			ctx: FileContext{
				Parameters: map[string]*Parameter{
					"BucketName": {
						inner: parameterInner{
							Type:    "String",
							Default: "test",
						},
					},
					"QueueName": {
						inner: parameterInner{
							Type: "String",
						},
					},
				},
			},
			arg: map[string]any{
				"BucketName": "test2",
				"QueueName":  "test",
				"SomeKey":    "some_value",
			},
			expected: map[string]*Parameter{
				"BucketName": {
					inner: parameterInner{
						Type:    "String",
						Default: "test2",
					},
				},
				"QueueName": {
					inner: parameterInner{
						Type:    "String",
						Default: "test",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ctx.OverrideParameters(tt.arg)
			assert.Equal(t, tt.expected, tt.ctx.Parameters)
		})
	}
}
