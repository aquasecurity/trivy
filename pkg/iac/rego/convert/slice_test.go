package convert

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_SliceConversion(t *testing.T) {
	input := []struct {
		X string
		Y int
		Z struct {
			A float64
		}
	}{
		{},
	}
	input[0].Z.A = 123
	converted := SliceToRego(reflect.ValueOf(input))
	assert.Equal(t, []any{map[string]any{"z": make(map[string]any)}}, converted)
}

func Test_SliceTypesConversion(t *testing.T) {
	input := []types.StringValue{
		types.String("test1", types.NewTestMetadata()),
		types.String("test2", types.NewTestMetadata()),
	}
	converted := SliceToRego(reflect.ValueOf(input))
	assert.Equal(t, []any{
		map[string]any{
			"value":        "test1",
			"filepath":     "test.test",
			"startline":    123,
			"endline":      123,
			"sourceprefix": "",
			"managed":      true,
			"unresolvable": false,
			"explicit":     false,
			"fskey":        "",
			"resource":     "",
		},
		map[string]any{
			"value":        "test2",
			"filepath":     "test.test",
			"startline":    123,
			"endline":      123,
			"sourceprefix": "",
			"managed":      true,
			"unresolvable": false,
			"explicit":     false,
			"fskey":        "",
			"resource":     "",
		},
	}, converted)
}
