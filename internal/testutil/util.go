package testutil

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func AssertRuleFound(t *testing.T, ruleID string, results scan.Results, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.True(t, found, append([]interface{}{message}, args...)...)
	for _, result := range results.GetFailed() {
		if result.Rule().LongID() == ruleID {
			m := result.Metadata()
			meta := &m
			for meta != nil {
				assert.NotNil(t, meta.Range(), 0)
				assert.Greater(t, meta.Range().GetStartLine(), 0)
				assert.Greater(t, meta.Range().GetEndLine(), 0)
				meta = meta.Parent()
			}
		}
	}
}

func AssertRuleNotFound(t *testing.T, ruleID string, results scan.Results, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.False(t, found, append([]interface{}{message}, args...)...)
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

func AssertDefsecEqual(t *testing.T, expected, actual interface{}) {
	expectedJson, err := json.MarshalIndent(expected, "", "\t")
	require.NoError(t, err)
	actualJson, err := json.MarshalIndent(actual, "", "\t")
	require.NoError(t, err)

	if expectedJson[0] == '[' {
		var expectedSlice []map[string]interface{}
		require.NoError(t, json.Unmarshal(expectedJson, &expectedSlice))
		var actualSlice []map[string]interface{}
		require.NoError(t, json.Unmarshal(actualJson, &actualSlice))
		expectedSlice = purgeMetadataSlice(expectedSlice)
		actualSlice = purgeMetadataSlice(actualSlice)
		assert.Equal(t, expectedSlice, actualSlice, "defsec adapted and expected values do not match")
	} else {
		var expectedMap map[string]interface{}
		require.NoError(t, json.Unmarshal(expectedJson, &expectedMap))
		var actualMap map[string]interface{}
		require.NoError(t, json.Unmarshal(actualJson, &actualMap))
		expectedMap = purgeMetadata(expectedMap)
		actualMap = purgeMetadata(actualMap)
		assert.Equal(t, expectedMap, actualMap, "defsec adapted and expected values do not match")
	}
}

func purgeMetadata(input map[string]interface{}) map[string]interface{} {
	for k, v := range input {
		if k == "metadata" || k == "Metadata" {
			delete(input, k)
			continue
		}
		if v, ok := v.(map[string]interface{}); ok {
			input[k] = purgeMetadata(v)
		}
		if v, ok := v.([]interface{}); ok {
			if len(v) > 0 {
				if _, ok := v[0].(map[string]interface{}); ok {
					maps := make([]map[string]interface{}, len(v))
					for i := range v {
						maps[i] = v[i].(map[string]interface{})
					}
					input[k] = purgeMetadataSlice(maps)
				}
			}
		}
	}
	return input
}

func purgeMetadataSlice(input []map[string]interface{}) []map[string]interface{} {
	for i := range input {
		input[i] = purgeMetadata(input[i])
	}
	return input
}
