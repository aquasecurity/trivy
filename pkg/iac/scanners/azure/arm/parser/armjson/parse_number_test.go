package armjson

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Number_IntToInt(t *testing.T) {
	example := []byte(`123`)
	var output int
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, 123, output)
}

func Test_Number_IntToFloat(t *testing.T) {
	example := []byte(`123`)
	var output float64
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, 123.0, output)
}

func Test_Number_FloatToFloat(t *testing.T) {
	example := []byte(`123.456`)
	var output float64
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, 123.456, output)
}

func Test_Number_FloatToInt(t *testing.T) {
	example := []byte(`123.456`)
	var output int
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.Equal(t, 123, output)
}

func Test_Number_FloatWithExponent(t *testing.T) {
	cases := []struct {
		in  string
		out float64
	}{
		{
			in:  `123.456e10`,
			out: 123.456e+10,
		},
		{
			in:  `123e+1`,
			out: 123e+1,
		},
		{
			in:  `123e-2`,
			out: 123e-2,
		},
	}
	for _, test := range cases {
		t.Run(test.in, func(t *testing.T) {
			example := []byte(test.in)
			var output float64
			metadata := types.NewTestMetadata()
			err := Unmarshal(example, &output, &metadata)
			require.NoError(t, err)
			assert.Equal(t, test.out, output)

		})
	}
}

func Test_Number_IntWithExponent(t *testing.T) {
	cases := []struct {
		in  string
		out int64
	}{
		{
			in:  `123e10`,
			out: 123e+10,
		},
		{
			in:  `123e+1`,
			out: 123e+1,
		},
	}
	for _, test := range cases {
		t.Run(test.in, func(t *testing.T) {
			example := []byte(test.in)
			var output int64
			metadata := types.NewTestMetadata()
			err := Unmarshal(example, &output, &metadata)
			require.NoError(t, err)
			assert.Equal(t, test.out, output)

		})
	}
}

func Test_Number_Ints(t *testing.T) {
	cases := []struct {
		in  string
		out int64
		err bool
	}{
		{
			in:  `123e10`,
			out: 123e+10,
		},
		{
			in:  `-1`,
			out: -1,
		},
		{
			in:  `1.0123`,
			out: 1,
		},
		{
			in:  `0`,
			out: 0,
		},
		{
			in:  `01`,
			err: true,
		},
		{
			in:  ``,
			err: true,
		},
		{
			in:  `+1`,
			err: true,
		},
		{
			in:  `e`,
			err: true,
		},

		{
			in:  `.123`,
			err: true,
		},

		{
			in:  `.`,
			err: true,
		},

		{
			in:  `00`,
			err: true,
		},
		{
			in:  `-`,
			err: true,
		},
	}
	for _, test := range cases {
		t.Run(test.in, func(t *testing.T) {
			example := []byte(test.in)
			var output int64
			metadata := types.NewTestMetadata()
			err := Unmarshal(example, &output, &metadata)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.out, output)
		})
	}
}
