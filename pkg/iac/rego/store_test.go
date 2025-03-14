package rego

import (
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitStore(t *testing.T) {
	fsys := fstest.MapFS{
		"test1.yml":      &fstest.MapFile{Data: []byte("foo: 1")},
		"test2.yaml":     &fstest.MapFile{Data: []byte("bar: 2")},
		"test3.json":     &fstest.MapFile{Data: []byte(`{"baz": 3}`)},
		"dir/test4.yaml": &fstest.MapFile{Data: []byte("qux: 4")},
	}
	store, err := initStore(fsys, []string{"."}, []string{"builtin.aws.test", "user.test"})
	require.NoError(t, err)

	tx, err := store.NewTransaction(t.Context())
	require.NoError(t, err)
	doc, err := store.Read(t.Context(), tx, storage.MustParsePath("/"))
	require.NoError(t, err)

	expected := map[string]any{
		"foo":        json.Number("1"),
		"bar":        json.Number("2"),
		"baz":        json.Number("3"),
		"qux":        json.Number("4"),
		"namespaces": []any{"builtin.aws.test", "user.test"},
	}
	assert.Equal(t, expected, doc)
}
