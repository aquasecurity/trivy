//go:build mage_helm

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		name                string
		currentHelmVersion  string
		currentTrivyVersion string
		newTrivyVersion     string
		newHelmVersion      string
	}{
		{
			"created the first patch",
			"0.1.0",
			"0.55.0",
			"0.55.1",
			"0.1.1",
		},
		{
			"created the second patch",
			"0.1.1",
			"0.55.1",
			"0.55.2",
			"0.1.2",
		},
		{
			"created the second patch but helm chart was changed",
			"0.1.2",
			"0.55.1",
			"0.55.2",
			"0.1.3",
		},
		{
			"created a new minor version",
			"0.1.1",
			"0.55.1",
			"0.56.0",
			"0.2.0",
		},
		{
			"created a new major version",
			"0.1.1",
			"0.55.1",
			"1.0.0",
			"1.0.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newHelmVersion, err := buildNewHelmVersion(test.currentHelmVersion, test.currentTrivyVersion, test.newTrivyVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.newHelmVersion, newHelmVersion)
		})
	}
}
