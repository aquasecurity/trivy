package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestSarifWriter_TerraformCodeFlows(t *testing.T) {
	var findings []types.DetectedMisconfiguration
	for _, caller := range []ftypes.Occurrence{
		{Filename: "service/main.tf", Resource: "module.rds_provisioner[0]", Location: ftypes.Location{StartLine: 1, EndLine: 18}},
		{Filename: "other/main.tf", Resource: "module.rds_provisioner[0]", Location: ftypes.Location{StartLine: 20, EndLine: 37}},
		{Filename: "service/main.tf", Resource: "module.rds_provisioner[1]", Location: ftypes.Location{StartLine: 1, EndLine: 18}},
	} {
		findings = append(findings, types.DetectedMisconfiguration{
			ID:       "AVD-AWS-0104",
			Severity: "HIGH",
			CauseMetadata: ftypes.CauseMetadata{
				StartLine: 80,
				EndLine:   80,
				Occurrences: []ftypes.Occurrence{
					{Filename: "module/lambda.tf", Resource: "aws_security_group_rule.egress_https_anywhere", Location: ftypes.Location{StartLine: 72, EndLine: 81}},
					caller,
				},
			},
		})
	}
	results, _ := writeSarifMisconfigurations(t, findings)
	require.Len(t, results, 3)
	require.Len(t, results[0].Locations, 1)
	primary := results[0].Locations[0].PhysicalLocation
	assert.Equal(t, "module/lambda.tf", *primary.ArtifactLocation.URI)
	assert.Equal(t, 80, *primary.Region.StartLine)
	assert.Equal(t, 80, *primary.Region.EndLine)
	for _, result := range results {
		require.Len(t, result.CodeFlows, 1)
		require.Len(t, result.CodeFlows[0].ThreadFlows, 1)
		require.Len(t, result.CodeFlows[0].ThreadFlows[0].Locations, 3)
		assert.Equal(t, results[0].Locations, result.Locations, "primary finding location must not change")
	}

	want, err := os.ReadFile("testdata/terraform-codeflow.sarif.golden")
	require.NoError(t, err)
	got, err := json.Marshal(results[0].CodeFlows)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(got))

	other := results[1].CodeFlows[0].ThreadFlows[0].Locations[0].Location
	assert.Equal(t, "other/main.tf", *other.PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 20, *other.PhysicalLocation.Region.StartLine)
	assert.Equal(t, 37, *other.PhysicalLocation.Region.EndLine)
	assert.Equal(t, "other/main.tf (module.rds_provisioner[0])", *other.Message.Text)
	otherInstance := results[2].CodeFlows[0].ThreadFlows[0].Locations[0].Location
	assert.Equal(t, "service/main.tf (module.rds_provisioner[1])", *otherInstance.Message.Text)
	assert.NotEqual(t, results[0].CodeFlows, results[2].CodeFlows, "instances at the same source location retain their resource context")
}

func TestSarifWriter_CodeFlowLocations(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		start, end int
		wantURI    string
		wantStart  int
		wantEnd    int
	}{
		{name: "Windows path with spaces", filename: `services\my app\main.tf`, start: 2, end: 5, wantURI: "services/my%20app/main.tf", wantStart: 2, wantEnd: 5},
		{name: "remote module", filename: "git@github.com:org/module.git?ref=v1/main.tf", start: 4, end: 9, wantURI: "github.com/org/module/tree/v1/main.tf", wantStart: 4, wantEnd: 9},
		{name: "literal percent", filename: "modules/100%/main.tf", start: 1, end: 1, wantURI: "modules/100%25/main.tf", wantStart: 1, wantEnd: 1},
		{name: "literal URI escape", filename: "env/100%20/main.tf", start: 1, end: 1, wantURI: "env/100%2520/main.tf", wantStart: 1, wantEnd: 1},
		{name: "hash in local path", filename: "env/prod#blue/main.tf", start: 1, end: 1, wantURI: "env/prod%23blue/main.tf", wantStart: 1, wantEnd: 1},
		{name: "question mark in local path", filename: "env/prod?blue/main.tf", start: 1, end: 1, wantURI: "env/prod%3Fblue/main.tf", wantStart: 1, wantEnd: 1},
		{name: "GitHub module shortcut", filename: "github.com/org/module?ref=v1/main.tf", start: 1, end: 1, wantURI: "github.com/org/module?ref=v1/main.tf", wantStart: 1, wantEnd: 1},
		{name: "HTTP module", filename: "https:/example.com/module?ref=v1/main.tf", start: 1, end: 1, wantURI: "https:/example.com/module?ref=v1/main.tf", wantStart: 1, wantEnd: 1},
		{name: "missing range", filename: "main.tf", wantURI: "main.tf", wantStart: 1, wantEnd: 1},
		{name: "missing end", filename: "main.tf", start: 8, wantURI: "main.tf", wantStart: 8, wantEnd: 8},
		{name: "missing start", filename: "main.tf", end: 8, wantURI: "main.tf", wantStart: 1, wantEnd: 8},
		{name: "reversed range", filename: "main.tf", start: 8, end: 2, wantURI: "main.tf", wantStart: 8, wantEnd: 8},
		{name: "negative range", filename: "main.tf", start: -2, end: -1, wantURI: "main.tf", wantStart: 1, wantEnd: 1},
		{name: "missing filename", start: 4, end: 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, _ := writeSarifMisconfigurations(t, []types.DetectedMisconfiguration{{
				ID: "AVD-AWS-0104",
				CauseMetadata: ftypes.CauseMetadata{
					StartLine: 80,
					EndLine:   80,
					Occurrences: []ftypes.Occurrence{{
						Filename: tt.filename,
						Resource: "module.example",
						Location: ftypes.Location{StartLine: tt.start, EndLine: tt.end},
					}},
				},
			}})
			require.Len(t, results[0].CodeFlows, 1)
			locations := results[0].CodeFlows[0].ThreadFlows[0].Locations
			require.Len(t, locations, 2)
			assert.Equal(t, 0, *locations[0].NestingLevel)
			assert.Equal(t, 1, *locations[1].NestingLevel)
			loc := locations[0].Location
			assert.Contains(t, *loc.Message.Text, "module.example")
			if tt.filename == "" {
				assert.Nil(t, loc.PhysicalLocation, "do not invent a file for an unknown caller")
				return
			}
			require.NotNil(t, loc.PhysicalLocation)
			assert.Equal(t, tt.wantURI, *loc.PhysicalLocation.ArtifactLocation.URI)
			assert.Equal(t, "ROOTPATH", *loc.PhysicalLocation.ArtifactLocation.URIBaseId)
			assert.Equal(t, tt.wantStart, *loc.PhysicalLocation.Region.StartLine)
			assert.Equal(t, tt.wantEnd, *loc.PhysicalLocation.Region.EndLine)
		})
	}
}

func TestSarifWriter_NoCodeFlowWithoutOccurrences(t *testing.T) {
	for _, occurrences := range [][]ftypes.Occurrence{nil, {}} {
		results, output := writeSarifMisconfigurations(t, []types.DetectedMisconfiguration{{
			ID: "AVD-AWS-0104",
			CauseMetadata: ftypes.CauseMetadata{
				StartLine:   80,
				EndLine:     80,
				Occurrences: occurrences,
			},
		}})
		assert.Nil(t, results[0].CodeFlows)
		assert.NotContains(t, output, "codeFlows")
		assert.Equal(t, "module/lambda.tf", *results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		assert.Equal(t, 80, *results[0].Locations[0].PhysicalLocation.Region.StartLine)
	}
}

func TestSarifWriter_CodeFlowCauseKeepsPrimaryURI(t *testing.T) {
	var output bytes.Buffer
	w := report.SarifWriter{Output: &output}
	require.NoError(t, w.Write(t.Context(), types.Report{Results: types.Results{{
		Target: "module/100%20/main.tf",
		Class:  types.ClassConfig,
		Type:   ftypes.Terraform,
		Misconfigurations: []types.DetectedMisconfiguration{{
			ID: "AVD-AWS-0104",
			CauseMetadata: ftypes.CauseMetadata{
				StartLine: 80,
				EndLine:   80,
				Occurrences: []ftypes.Occurrence{{
					Filename: "service/main.tf",
					Resource: "module.example",
					Location: ftypes.Location{StartLine: 1, EndLine: 18},
				}},
			},
		}},
	}}}))
	var result sarif.Report
	require.NoError(t, json.Unmarshal(output.Bytes(), &result))
	finding := result.Runs[0].Results[0]
	primary := finding.Locations[0].PhysicalLocation.ArtifactLocation
	assert.Equal(t, "module/100%20/main.tf", *primary.URI)
	locations := finding.CodeFlows[0].ThreadFlows[0].Locations
	assert.Equal(t, primary, locations[len(locations)-1].Location.PhysicalLocation.ArtifactLocation)
}

func writeSarifMisconfigurations(t *testing.T, findings []types.DetectedMisconfiguration) ([]*sarif.Result, string) {
	t.Helper()
	var output bytes.Buffer
	w := report.SarifWriter{Output: &output}
	require.NoError(t, w.Write(t.Context(), types.Report{Results: types.Results{{
		Target:            "module/lambda.tf",
		Class:             types.ClassConfig,
		Type:              ftypes.Terraform,
		Misconfigurations: findings,
	}}}))
	var result sarif.Report
	require.NoError(t, json.Unmarshal(output.Bytes(), &result))
	require.Len(t, result.Runs, 1)
	return result.Runs[0].Results, output.String()
}
