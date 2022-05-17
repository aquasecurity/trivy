package k8s

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

var (
	deployOrionWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{Misconfigurations: []types.DetectedMisconfiguration{{ID: "ID100", Status: types.StatusFailure}}},
		},
	}

	deployOrionWithVulns = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2020-8888"}}},
		},
	}

	deployOrionWithBothVulnsAndMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Deploy",
		Name:      "orion",
		Results: types.Results{
			{Misconfigurations: []types.DetectedMisconfiguration{{ID: "ID100", Status: types.StatusFailure}}},
			{Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2020-8888"}}},
		},
	}

	cronjobHelloWithVulns = Resource{
		Namespace: "default",
		Kind:      "Cronjob",
		Name:      "hello",
		Results: types.Results{
			{Vulnerabilities: []types.DetectedVulnerability{{VulnerabilityID: "CVE-2020-9999"}}},
		},
	}

	podPrometheusWithMisconfigs = Resource{
		Namespace: "default",
		Kind:      "Pod",
		Name:      "prometheus",
		Results: types.Results{
			{Misconfigurations: []types.DetectedMisconfiguration{{ID: "ID100"}}},
		},
	}
)

func TestReport_consolidate(t *testing.T) {
	tests := []struct {
		name             string
		report           Report
		expectedFindings map[string]Resource
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Vulnerabilities:   []Resource{deployOrionWithVulns, cronjobHelloWithVulns},
				Misconfigurations: []Resource{deployOrionWithMisconfigs, podPrometheusWithMisconfigs},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithBothVulnsAndMisconfigs,
				"default/cronjob/hello":  cronjobHelloWithVulns,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Misconfigurations: []Resource{deployOrionWithMisconfigs, podPrometheusWithMisconfigs},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":   deployOrionWithMisconfigs,
				"default/pod/prometheus": podPrometheusWithMisconfigs,
			},
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{deployOrionWithVulns, cronjobHelloWithVulns},
			},
			expectedFindings: map[string]Resource{
				"default/deploy/orion":  deployOrionWithVulns,
				"default/cronjob/hello": cronjobHelloWithVulns,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consolidateReport := tt.report.consolidate()
			for _, f := range consolidateReport.Findings {
				key := f.fullname()

				expected, found := tt.expectedFindings[key]
				if !found {
					t.Errorf("key not found: %s", key)
				}

				assert.Equal(t, expected, f)
			}
		})
	}
}

func TestResource_fullname(t *testing.T) {
	tests := []struct {
		expected string
		resource Resource
	}{
		{"default/deploy/orion", deployOrionWithBothVulnsAndMisconfigs},
		{"default/deploy/orion", deployOrionWithMisconfigs},
		{"default/cronjob/hello", cronjobHelloWithVulns},
		{"default/pod/prometheus", podPrometheusWithMisconfigs},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.resource.fullname())
		})
	}
}

func TestResourceFailed(t *testing.T) {
	tests := []struct {
		name     string
		report   Report
		expected bool
	}{
		{
			name: "report with both misconfigs and vulnerabilities",
			report: Report{
				Vulnerabilities:   []Resource{deployOrionWithVulns, cronjobHelloWithVulns},
				Misconfigurations: []Resource{deployOrionWithMisconfigs, podPrometheusWithMisconfigs},
			},
			expected: true,
		},
		{
			name: "report with only misconfigurations",
			report: Report{
				Misconfigurations: []Resource{deployOrionWithMisconfigs, podPrometheusWithMisconfigs},
			},
			expected: true,
		},
		{
			name: "report with only vulnerabilities",
			report: Report{
				Vulnerabilities: []Resource{deployOrionWithVulns, cronjobHelloWithVulns},
			},
			expected: true,
		},
		{
			name:     "report without vulnerabilities and misconfigurations",
			report:   Report{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.report.Failed())
		})
	}
}
