package dockerfile_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/config/parser/dockerfile"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      interface{}
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/Dockerfile",
			want: map[string]interface{}{
				"stages": map[string]interface{}{
					"foo": []interface{}{
						map[string]interface{}{
							"Cmd":       "from",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "FROM foo",
							"Stage":     float64(0),
							"StartLine": float64(1),
							"EndLine":   float64(1),
							"SubCmd":    "",
							"Value":     []interface{}{"foo"},
						},
						map[string]interface{}{
							"Cmd":       "copy",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "COPY . /",
							"Stage":     float64(0),
							"StartLine": float64(2),
							"EndLine":   float64(2),
							"SubCmd":    "",
							"Value":     []interface{}{".", "/"},
						},
						map[string]interface{}{
							"Cmd":       "run",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "RUN echo hello",
							"Stage":     float64(0),
							"StartLine": float64(3),
							"EndLine":   float64(3),
							"SubCmd":    "",
							"Value":     []interface{}{"echo hello"},
						},
					},
				},
			},
		},
		{
			name:      "multi stage",
			inputFile: "testdata/Dockerfile.multi",
			want: map[string]interface{}{
				"stages": map[string]interface{}{
					"golang:1.16 AS builder": []interface{}{
						map[string]interface{}{
							"Cmd":       "from",
							"EndLine":   float64(1),
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "FROM golang:1.16 AS builder",
							"Stage":     float64(0),
							"StartLine": float64(1),
							"SubCmd":    "",
							"Value":     []interface{}{"golang:1.16", "AS", "builder"},
						},
						map[string]interface{}{
							"Cmd":       "workdir",
							"EndLine":   float64(2),
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "WORKDIR /go/src/github.com/alexellis/href-counter/",
							"Stage":     float64(0),
							"StartLine": float64(2),
							"SubCmd":    "",
							"Value":     []interface{}{"/go/src/github.com/alexellis/href-counter/"},
						},
						map[string]interface{}{
							"Cmd":       "run",
							"EndLine":   float64(3),
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "RUN go get -d -v golang.org/x/net/html",
							"Stage":     float64(0),
							"StartLine": float64(3),
							"SubCmd":    "",
							"Value":     []interface{}{"go get -d -v golang.org/x/net/html"},
						},
						map[string]interface{}{
							"Cmd":       "copy",
							"EndLine":   float64(4),
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "COPY app.go .",
							"Stage":     float64(0),
							"StartLine": float64(4),
							"SubCmd":    "",
							"Value":     []interface{}{"app.go", "."},
						},
						map[string]interface{}{
							"Cmd":       "run",
							"EndLine":   float64(5),
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .",
							"Stage":     float64(0),
							"StartLine": float64(5),
							"SubCmd":    "",
							"Value":     []interface{}{"CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."},
						},
					},
					"alpine:latest": []interface{}{
						map[string]interface{}{
							"Cmd":       "from",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "FROM alpine:latest",
							"Stage":     float64(1),
							"StartLine": float64(7),
							"EndLine":   float64(7),
							"SubCmd":    "",
							"Value":     []interface{}{"alpine:latest"},
						},
						map[string]interface{}{
							"Cmd":       "run",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "RUN apk --no-cache add ca-certificates     && apk add --no-cache bash",
							"Stage":     float64(1),
							"StartLine": float64(8),
							"EndLine":   float64(9),
							"SubCmd":    "",
							"Value":     []interface{}{"apk --no-cache add ca-certificates     && apk add --no-cache bash"},
						},
						map[string]interface{}{
							"Cmd":       "workdir",
							"Flags":     []interface{}{},
							"JSON":      false,
							"Original":  "WORKDIR /root/",
							"Stage":     float64(1),
							"StartLine": float64(10),
							"EndLine":   float64(10),
							"SubCmd":    "",
							"Value":     []interface{}{"/root/"},
						},
						map[string]interface{}{
							"Cmd":       "copy",
							"Flags":     []interface{}{"--from=builder"},
							"JSON":      false,
							"Original":  "COPY --from=builder /go/src/github.com/alexellis/href-counter/app .",
							"Stage":     float64(1),
							"StartLine": float64(11),
							"EndLine":   float64(11),
							"SubCmd":    "",
							"Value":     []interface{}{"/go/src/github.com/alexellis/href-counter/app", "."},
						},
						map[string]interface{}{
							"Cmd":       "cmd",
							"Flags":     []interface{}{},
							"JSON":      true,
							"Original":  `CMD ["./app"]`,
							"Stage":     float64(1),
							"StartLine": float64(12),
							"EndLine":   float64(12),
							"SubCmd":    "",
							"Value":     []interface{}{"./app"},
						},
					},
				},
			},
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
			assert.Equal(t, tt.want, got)
		})
	}
}
