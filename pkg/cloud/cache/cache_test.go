package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cloud/report"
)

func TestCache(t *testing.T) {

	tests := []struct {
		name     string
		input    report.Report
		services []string
	}{
		{
			name: "no services",
			input: report.Report{
				Provider:        "AWS",
				AccountID:       "1234567890",
				Region:          "us-east-1",
				Results:         make(map[string]report.ResultsAtTime),
				ServicesInScope: nil,
			},
			services: nil,
		},
		{
			name: "all services",
			input: report.Report{
				Provider:  "AWS",
				AccountID: "1234567890",
				Region:    "us-east-1",
				Results: map[string]report.ResultsAtTime{
					"s3": {
						Results:      nil,
						CreationTime: time.Now(),
					},
					"ec2": {
						Results:      nil,
						CreationTime: time.Now(),
					},
				},
				ServicesInScope: []string{"ec2", "s3"},
			},
			services: []string{"ec2", "s3"},
		},
		{
			name: "partial services",
			input: report.Report{
				Provider:  "AWS",
				AccountID: "1234567890",
				Region:    "us-east-1",
				Results: map[string]report.ResultsAtTime{
					"s3": {
						Results:      nil,
						CreationTime: time.Now(),
					},
					"ec2": {
						Results:      nil,
						CreationTime: time.Now(),
					},
				},
				ServicesInScope: []string{"ec2", "s3"},
			},
			services: []string{"ec2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			baseDir := t.TempDir()

			// ensure saving doesn't error
			cache := New(baseDir, time.Hour, test.input.Provider, test.input.AccountID, test.input.Region)
			require.NoError(t, cache.Save(&test.input))

			// ensure all scoped services were cached
			available := cache.ListAvailableServices(false)
			assert.Equal(t, test.input.ServicesInScope, available)

			// ensure all cached services are really available
			fullReport, err := cache.LoadReport(available...)
			require.NoError(t, err)
			assert.Equal(t, available, fullReport.ServicesInScope)

			// ensure loading restores all (specified) data
			loaded, err := cache.LoadReport(test.services...)
			require.NoError(t, err)

			assert.Equal(t, test.input.Provider, loaded.Provider)
			assert.Equal(t, test.input.AccountID, loaded.AccountID)
			assert.Equal(t, test.input.Region, loaded.Region)
			assert.Equal(t, test.services, loaded.ServicesInScope)

			var actualServices []string
			for service := range loaded.Results {
				actualServices = append(actualServices, service)
			}
			assert.Equal(t, test.services, actualServices)

			for _, service := range test.services {
				assert.Equal(t, test.input.Results[service].CreationTime.Format(time.RFC3339), loaded.Results[service].CreationTime.Format(time.RFC3339))
				assert.Equal(t, test.input.Results[service].Results, loaded.Results[service].Results)
			}
		})
	}
}

func TestPartialCacheOverwrite(t *testing.T) {
	baseDir := t.TempDir()

	r1 := report.Report{
		Provider:  "AWS",
		AccountID: "1234567890",
		Region:    "us-east-1",
		Results: map[string]report.ResultsAtTime{
			"a": {
				Results:      nil,
				CreationTime: time.Now(),
			},
			"b": {
				Results:      nil,
				CreationTime: time.Now(),
			},
			"c": {
				Results:      nil,
				CreationTime: time.Now(),
			},
			"d": {
				Results:      nil,
				CreationTime: time.Now(),
			},
		},
		ServicesInScope: []string{"a", "b", "c", "d"},
	}

	// ensure saving doesn't error
	cache := New(baseDir, time.Hour, "AWS", "1234567890", "us-east-1")
	require.NoError(t, cache.Save(&r1))

	r2 := report.Report{
		Provider:  "AWS",
		AccountID: "1234567890",
		Region:    "us-east-1",
		Results: map[string]report.ResultsAtTime{
			"a": {
				Results:      nil,
				CreationTime: time.Now(),
			},
			"b": {
				Results:      nil,
				CreationTime: time.Now(),
			},
		},
		ServicesInScope: []string{"a", "b"},
	}
	require.NoError(t, cache.Save(&r2))

	assert.Equal(t, []string{"a", "b", "c", "d"}, cache.ListAvailableServices(false))
}
