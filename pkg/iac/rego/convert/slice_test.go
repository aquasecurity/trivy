package convert

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, []interface{}{map[string]interface{}{"z": map[string]interface{}{}}}, converted)
}

func Test_SliceTypesConversion(t *testing.T) {
	input := []types.StringValue{
		types.String("test1", types.NewTestMetadata()),
		types.String("test2", types.NewTestMetadata()),
	}
	converted := SliceToRego(reflect.ValueOf(input))
	assert.Equal(t, []interface{}{
		map[string]interface{}{
			"value":        "test1",
			"filepath":     "test.test",
			"startline":    123,
			"endline":      123,
			"sourceprefix": "",
			"managed":      true,
			"explicit":     false,
			"fskey":        "",
			"resource":     "",
		},
		map[string]interface{}{
			"value":        "test2",
			"filepath":     "test.test",
			"startline":    123,
			"endline":      123,
			"sourceprefix": "",
			"managed":      true,
			"explicit":     false,
			"fskey":        "",
			"resource":     "",
		},
	}, converted)
}
