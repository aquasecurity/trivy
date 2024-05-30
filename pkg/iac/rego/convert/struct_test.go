package convert

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StructConversion(t *testing.T) {
	input := struct {
		X string
		Y int
		Z struct {
			A float64
		}
	}{}
	input.Z.A = 123
	converted := StructToRego(reflect.ValueOf(input))
	assert.Equal(t, map[string]any{"z": make(map[string]any)}, converted)
}
