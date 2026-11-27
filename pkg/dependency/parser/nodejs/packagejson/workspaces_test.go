package packagejson

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The workspaces field is part of the scanned repository, so any shape a user
// can write reaches ParseWorkspaces.  These are the ones npm's schema does not
// allow but nothing stops a package.json from containing.
func TestParseWorkspacesMalformed(t *testing.T) {
	cases := []struct {
		name string
		val  any
	}{
		{"packages is a string", map[string]any{"packages": "packages/*"}},
		{"packages is an object", map[string]any{"packages": map[string]any{"a": "b"}}},
		{"array holds a number", []any{"packages/*", 1.0}},
		{"array holds an object", []any{"packages/*", map[string]any{"a": "b"}}},
		{"array holds null", []any{"packages/*", nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				got := ParseWorkspaces(c.val)
				t.Logf("-> %v", got)
			})
		})
	}
}

// The shapes npm documents must keep working exactly as before.
func TestParseWorkspacesValid(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want []string
	}{
		{"string array", []any{"packages/*", "backend"}, []string{"packages/*", "backend"}},
		{"object with packages", map[string]any{"packages": []any{"packages/*"}}, []string{"packages/*"}},
		{"object without packages", map[string]any{"nohoist": []any{"a"}}, nil},
		{"string (unsupported shape, ignored)", "packages/*", nil},
		{"nil", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ParseWorkspaces(c.val))
		})
	}
}

// End to end: a package.json with a malformed workspaces field must still be
// parsed rather than taking the scan down.
func TestParserWorkspacesNeverPanics(t *testing.T) {
	const doc = `{
  "name": "app",
  "version": "1.0.0",
  "workspaces": {"packages": "packages/*"}
}`
	p, err := NewParser().Parse(strings.NewReader(doc))
	require.NoError(t, err)
	assert.Equal(t, "app", p.Name)
	assert.Empty(t, p.Workspaces)
}
