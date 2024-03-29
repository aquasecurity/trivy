package pip

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string
		want []types.Library
	}{
		{
			file: "testdata/requirements_flask.txt",
			want: requirementsFlask,
		},
		{
			file: "testdata/requirements_comments.txt",
			want: requirementsComments,
		},
		{
			file: "testdata/requirements_spaces.txt",
			want: requirementsSpaces,
		},
		{
			file: "testdata/requirements_no_version.txt",
			want: requirementsNoVersion,
		},
		{
			file: "testdata/requirements_operator.txt",
			want: requirementsOperator,
		},
		{
			file: "testdata/requirements_hash.txt",
			want: requirementsHash,
		},
		{
			file: "testdata/requirements_hyphens.txt",
			want: requirementsHyphens,
		},
		{
			file: "testdata/requirement_exstras.txt",
			want: requirementsExtras,
		},
		{
			file: "testdata/requirements_utf16le.txt",
			want: requirementsUtf16le,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
