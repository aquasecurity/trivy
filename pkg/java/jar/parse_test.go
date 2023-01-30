package jar_test

import (
	"encoding/json"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar/sonatype"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	// cd testdata/testimage/maven && docker build -t test .
	// docker run --rm --name test -it test bash
	// mvn dependency:list
	// mvn dependency:tree -Dscope=compile -Dscope=runtime | awk '/:tree/,/BUILD SUCCESS/' | awk 'NR > 1 { print }' | head -n -2 | awk '{print $NF}' | awk -F":" '{printf("{\""$1":"$2"\", \""$4 "\", \"\"},\n")}'
	wantMaven = []types.Library{
		{
			Name:    "com.example:web-app",
			Version: "1.0-SNAPSHOT",
		},
		{
			Name:    "com.fasterxml.jackson.core:jackson-databind",
			Version: "2.9.10.6",
		},
		{
			Name:    "com.fasterxml.jackson.core:jackson-annotations",
			Version: "2.9.10",
		},
		{
			Name:    "com.fasterxml.jackson.core:jackson-core",
			Version: "2.9.10",
		},
		{
			Name:    "com.cronutils:cron-utils",
			Version: "9.1.2",
		},
		{
			Name:    "org.slf4j:slf4j-api",
			Version: "1.7.30",
		},
		{
			Name:    "org.glassfish:javax.el",
			Version: "3.0.0",
		},
		{
			Name:    "org.apache.commons:commons-lang3",
			Version: "3.11",
		},
	}

	// cd testdata/testimage/gradle && docker build -t test .
	// docker run --rm --name test -it test bash
	// gradle app:dependencies --configuration implementation | grep "[+\]---" | cut -d" " -f2 | awk -F":" '{printf("{\""$1":"$2"\", \""$3"\", \"\"},\n")}'
	wantGradle = []types.Library{
		{
			Name:    "commons-dbcp:commons-dbcp",
			Version: "1.4",
		},
		{
			Name:    "commons-pool:commons-pool",
			Version: "1.6",
		},
		{
			Name:    "log4j:log4j",
			Version: "1.2.17",
		},
		{
			Name:    "org.apache.commons:commons-compress",
			Version: "1.19",
		},
	}

	// manually created
	wantSHA1 = []types.Library{
		{
			Name:    "org.springframework:spring-core",
			Version: "5.3.3",
		},
	}

	// offline
	wantOffline = []types.Library{
		{
			Name:    "org.springframework:Spring Framework",
			Version: "2.5.6.SEC03",
		},
	}

	// manually created
	wantHeuristic = []types.Library{
		{
			Name:    "com.example:heuristic",
			Version: "1.0.0-SNAPSHOT",
		},
	}

	// manually created
	wantFatjar = []types.Library{
		{
			Name:    "com.google.guava:failureaccess",
			Version: "1.0.1",
		},
		{
			Name:    "com.google.guava:guava",
			Version: "29.0-jre",
		},
		{
			Name:    "com.google.guava:listenablefuture",
			Version: "9999.0-empty-to-avoid-conflict-with-guava",
		},
		{
			Name:    "com.google.j2objc:j2objc-annotations",
			Version: "1.3",
		},
		{
			Name:    "org.apache.hadoop.thirdparty:hadoop-shaded-guava",
			Version: "1.1.0-SNAPSHOT",
		},
	}
)

type apiResponse struct {
	Response response `json:"response"`
}

type response struct {
	NumFound int   `json:"numFound"`
	Docs     []doc `json:"docs"`
}

type doc struct {
	ID           string `json:"id"`
	GroupID      string `json:"g"`
	ArtifactID   string `json:"a"`
	Version      string `json:"v"`
	P            string `json:"p"`
	VersionCount int    `json:versionCount`
}

func TestParse(t *testing.T) {
	vectors := []struct {
		name    string
		file    string // Test input file
		offline bool
		want    []types.Library
	}{
		{
			name: "maven",
			file: "testdata/maven.war",
			want: wantMaven,
		},
		{
			name: "gradle",
			file: "testdata/gradle.war",
			want: wantGradle,
		},
		{
			name: "sha1 search",
			file: "testdata/test.jar",
			want: wantSHA1,
		},
		{
			name:    "offline",
			file:    "testdata/test.jar",
			offline: true,
			want:    wantOffline,
		},
		{
			name: "artifactId search",
			file: "testdata/heuristic-1.0.0-SNAPSHOT.jar",
			want: wantHeuristic,
		},
		{
			name: "fat jar",
			file: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
			want: wantFatjar,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := apiResponse{
			Response: response{
				NumFound: 1,
			},
		}

		switch {
		case strings.Contains(r.URL.Query().Get("q"), "springframework"):
			res.Response.NumFound = 0
		case strings.Contains(r.URL.Query().Get("q"), "c666f5bc47eb64ed3bbd13505a26f58be71f33f0"):
			res.Response.Docs = []doc{
				{
					ID:         "org.springframework.spring-core",
					GroupID:    "org.springframework",
					ArtifactID: "spring-core",
					Version:    "5.3.3",
				},
			}
		case strings.Contains(r.URL.Query().Get("q"), "heuristic"):
			res.Response.Docs = []doc{
				{
					ID:           "org.springframework.heuristic",
					GroupID:      "org.springframework",
					ArtifactID:   "heuristic",
					VersionCount: 10,
				},
				{
					ID:           "com.example.heuristic",
					GroupID:      "com.example",
					ArtifactID:   "heuristic",
					VersionCount: 100,
				},
			}
		}
		_ = json.NewEncoder(w).Encode(res)
	}))

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			stat, err := f.Stat()
			require.NoError(t, err)

			c := sonatype.New(sonatype.WithURL(ts.URL), sonatype.WithHTTPClient(ts.Client()))
			p := jar.NewParser(c, jar.WithFilePath(v.file), jar.WithOffline(v.offline), jar.WithSize(stat.Size()))

			got, _, err := p.Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(v.want, func(i, j int) bool {
				return v.want[i].Name < v.want[j].Name
			})

			assert.Equal(t, v.want, got)
		})
	}
}
