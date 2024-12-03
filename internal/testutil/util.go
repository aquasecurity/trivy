package testutil

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liamg/memoryfs"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func AssertRuleFound(t *testing.T, ruleID string, results scan.Results, message string, args ...any) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.True(t, found, append([]any{message}, args...)...)
	for _, result := range results.GetFailed() {
		if result.Rule().LongID() == ruleID {
			m := result.Metadata()
			meta := &m
			for meta != nil {
				assert.NotNil(t, meta.Range(), 0)
				assert.Positive(t, meta.Range().GetStartLine())
				assert.Positive(t, meta.Range().GetEndLine())
				meta = meta.Parent()
			}
		}
	}
}

func AssertRuleNotFound(t *testing.T, ruleID string, results scan.Results, message string, args ...any) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.False(t, found, append([]any{message}, args...)...)
}

func AssertRuleNotFailed(t *testing.T, ruleID string, results scan.Results, message string, args ...any) {
	failedExists := ruleIDInResults(ruleID, results.GetFailed())
	assert.False(t, failedExists, append([]any{message}, args...)...)
	passedResults := lo.Filter(results, func(res scan.Result, _ int) bool {
		return res.Status() == scan.StatusPassed || res.Status() == scan.StatusIgnored
	})
	passedExists := ruleIDInResults(ruleID, passedResults)
	assert.True(t, passedExists, append([]any{message}, args...)...)
}

func ruleIDInResults(ruleID string, results scan.Results) bool {
	for _, res := range results {
		if res.Rule().LongID() == ruleID {
			return true
		}
	}
	return false
}

func CreateFS(t *testing.T, files map[string]string) fs.FS {
	memfs := memoryfs.New()
	for name, content := range files {
		name := strings.TrimPrefix(name, "/")
		err := memfs.MkdirAll(filepath.Dir(name), 0o700)
		require.NoError(t, err)
		err = memfs.WriteFile(name, []byte(content), 0o644)
		require.NoError(t, err)
	}
	return memfs
}

func AssertDefsecEqual(t *testing.T, expected, actual any) {
	expectedJson, err := json.MarshalIndent(expected, "", "\t")
	require.NoError(t, err)
	actualJson, err := json.MarshalIndent(actual, "", "\t")
	require.NoError(t, err)

	if expectedJson[0] == '[' {
		var expectedSlice []map[string]any
		require.NoError(t, json.Unmarshal(expectedJson, &expectedSlice))
		var actualSlice []map[string]any
		require.NoError(t, json.Unmarshal(actualJson, &actualSlice))
		expectedSlice = purgeMetadataSlice(expectedSlice)
		actualSlice = purgeMetadataSlice(actualSlice)
		assert.Equal(t, expectedSlice, actualSlice, "defsec adapted and expected values do not match")
	} else {
		var expectedMap map[string]any
		require.NoError(t, json.Unmarshal(expectedJson, &expectedMap))
		var actualMap map[string]any
		require.NoError(t, json.Unmarshal(actualJson, &actualMap))
		expectedMap = purgeMetadata(expectedMap)
		actualMap = purgeMetadata(actualMap)
		assert.Equal(t, expectedMap, actualMap, "defsec adapted and expected values do not match")
	}
}

func purgeMetadata(input map[string]any) map[string]any {
	for k, v := range input {
		if k == "metadata" || k == "Metadata" {
			delete(input, k)
			continue
		}
		if v, ok := v.(map[string]any); ok {
			input[k] = purgeMetadata(v)
		}
		if v, ok := v.([]any); ok {
			if len(v) > 0 {
				if _, ok := v[0].(map[string]any); ok {
					maps := make([]map[string]any, len(v))
					for i := range v {
						maps[i] = v[i].(map[string]any)
					}
					input[k] = purgeMetadataSlice(maps)
				}
			}
		}
	}
	return input
}

func purgeMetadataSlice(input []map[string]any) []map[string]any {
	for i := range input {
		input[i] = purgeMetadata(input[i])
	}
	return input
}
