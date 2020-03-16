package internal

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"

	"github.com/stretchr/testify/assert"
)

type fakeIOWriter struct {
	written []byte
}

func (f *fakeIOWriter) Write(p []byte) (n int, err error) {
	f.written = append(f.written, p...)
	return len(p), nil
}

func Test_showVersion(t *testing.T) {
	type args struct {
		cacheDir     string
		outputFormat string
		version      string
	}
	tests := []struct {
		name           string
		args           args
		createDB       bool
		expectedOutput string
	}{
		{
			name: "happy path, table output",
			args: args{
				outputFormat: "table",
				version:      "1.2.3",
			},
			expectedOutput: `+------------------+-------------------------------+
|    COMPONENT     |            VERSION            |
+------------------+-------------------------------+
| Trivy            | 1.2.3                         |
| Vulnerability DB | 2020-03-16 16:40:20 -0700 PDT |
+------------------+-------------------------------+
`,
			createDB: true,
		},
		{
			name: "happy path, JSON output",
			args: args{
				outputFormat: "json",
				version:      "1.2.3",
			},
			expectedOutput: `{"TrivyVersion":"1.2.3","VulnerabilityDBVersion":{"Version":42,"Type":1,"NextUpdate":"2020-03-16T16:57:00-07:00","UpdatedAt":"2020-03-16T16:40:20-07:00"}}
`,
			createDB: true,
		},
		{
			name: "sad path, no DB is available",
			args: args{
				outputFormat: "table",
				version:      "1.2.3",
			},
			expectedOutput: `unable to display current version: unexpected end of JSON input`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, _ := ioutil.TempDir("", "Test_showVersion-*")
			defer func() {
				os.RemoveAll(d)
			}()

			if tt.createDB {
				db.Init(d)
				db.Config{}.SetMetadata(db.Metadata{
					Version:    42,
					Type:       1,
					NextUpdate: time.Unix(1584403020, 0),
					UpdatedAt:  time.Unix(1584402020, 0),
				})
				db.Close()
			}

			var wb []byte
			fw := fakeIOWriter{written: wb}

			showVersion(d, tt.args.outputFormat, tt.args.version, &fw)
			assert.Equal(t, tt.expectedOutput, string(fw.written), tt.name)
		})
	}
}
