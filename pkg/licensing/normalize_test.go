package licensing_test

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestLicenseSplitRegexp(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		licenses []string
	}{
		{
			"simple list commad-separated",
			"GPL-1+,GPL-2",
			[]string{"GPL-1+", "GPL-2"},
		},
		{
			"simple list commad-separated",
			"GPL-1+,GPL-2,GPL-3",
			[]string{"GPL-1+", "GPL-2", "GPL-3"},
		},
		{
			"3 licenses 'or'-separated",
			"GPL-1+ or Artistic or Artistic-dist",
			[]string{"GPL-1+", "Artistic", "Artistic-dist"},
		},
		// '
		{
			"two licenses _or_ separated",
			"LGPLv3+_or_GPLv2+",
			[]string{"LGPLv3+", "GPLv2+"},
		},
		// '
		{
			"licenses `and`-separated",
			"BSD-3-CLAUSE and GPL-2",
			[]string{"BSD-3-CLAUSE", "GPL-2"},
		},
		{
			"three licenses and/or separated",
			"GPL-1+ or Artistic, and BSD-4-clause-POWERDOG",
			[]string{"GPL-1+", "Artistic", "BSD-4-clause-POWERDOG"},
		},
		{
			"two licenses with version",
			"BSD 3-Clause License or Apache License, Version 2.0",
			[]string{"BSD 3-Clause License", "Apache License, Version 2.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := licensing.LicenseSplitRegexp.Split(tt.license, -1)
			assert.Equal(t, tt.licenses, res)
		})
	}
}
