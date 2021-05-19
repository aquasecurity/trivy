package dockerfile_test

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/config/parser/dockerfile"
)

func Test_dockerParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      string
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/Dockerfile.deployment",
			want:      `{"command":{"foo":[{"Cmd":"from","EndLine":1,"Flags":[],"JSON":false,"Original":"FROM foo","Stage":0,"StartLine":1,"SubCmd":"","Value":["foo"]},{"Cmd":"copy","EndLine":2,"Flags":[],"JSON":false,"Original":"COPY . /","Stage":0,"StartLine":2,"SubCmd":"","Value":[".","/"]},{"Cmd":"run","EndLine":3,"Flags":[],"JSON":false,"Original":"RUN echo hello","Stage":0,"StartLine":3,"SubCmd":"","Value":["echo hello"]}]}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			p := dockerfile.Parser{}
			got, err := p.Parse(b)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			gotJson, err := json.Marshal(got)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, string(gotJson))
		})
	}
}
