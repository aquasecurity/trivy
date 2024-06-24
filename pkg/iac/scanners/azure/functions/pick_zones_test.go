package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PickZones(t *testing.T) {
	assert.Equal(t, []int{1}, PickZones("Microsoft.Compute", "virtualmachines", "eu-west-1"))
	assert.Equal(t, []int{1, 2}, PickZones("Microsoft.Compute", "virtualmachines", "eu-west-1", 2))
	assert.Equal(t, []int{1, 2, 3}, PickZones("Microsoft.Compute", "virtualmachines", "eu-west-1", 3))
	assert.Equal(t, []int{1, 2, 3}, PickZones("Microsoft.Compute", "virtualmachines", "eu-west-1", 4))
}
