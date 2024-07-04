package jar_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar/sonatype"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	// cd testdata/testimage/maven && docker build -t test .
	// docker run --rm --name test -it test bash
	// mvn dependency:list
	// mvn dependency:tree -Dscope=compile -Dscope=runtime | awk '/:tree/,/BUILD SUCCESS/' | awk 'NR > 1 { print }' | head -n -2 | awk '{print $NF}' | awk -F":" '{printf("{\""$1":"$2"\", \""$4 "\", \"\"},\n")}'
	// paths filled in manually
	wantMaven = []ftypes.Package{
		{
			Name:     "com.example:web-app",
			Version:  "1.0-SNAPSHOT",
			FilePath: "testdata/maven.war",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.9.10.6",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-databind-2.9.10.6.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-annotations",
			Version:  "2.9.10",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-annotations-2.9.10.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-core",
			Version:  "2.9.10",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-core-2.9.10.jar",
		},
		{
			Name:     "com.cronutils:cron-utils",
			Version:  "9.1.2",
			FilePath: "testdata/maven.war/WEB-INF/lib/cron-utils-9.1.2.jar",
		},
		{
			Name:     "org.slf4j:slf4j-api",
			Version:  "1.7.30",
			FilePath: "testdata/maven.war/WEB-INF/lib/slf4j-api-1.7.30.jar",
		},
		{
			Name:     "org.glassfish:javax.el",
			Version:  "3.0.0",
			FilePath: "testdata/maven.war/WEB-INF/lib/javax.el-3.0.0.jar",
		},
		{
			Name:     "org.apache.commons:commons-lang3",
			Version:  "3.11",
			FilePath: "testdata/maven.war/WEB-INF/lib/commons-lang3-3.11.jar",
		},
	}

	// cd testdata/testimage/gradle && docker build -t test .
	// docker run --rm --name test -it test bash
	// gradle app:dependencies --configuration implementation | grep "[+\]---" | cut -d" " -f2 | awk -F":" '{printf("{\""$1":"$2"\", \""$3"\", \"\"},\n")}'
	// paths filled in manually
	wantGradle = []ftypes.Package{
		{
			Name:     "commons-dbcp:commons-dbcp",
			Version:  "1.4",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-dbcp-1.4.jar",
		},
		{
			Name:     "commons-pool:commons-pool",
			Version:  "1.6",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-pool-1.6.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.17",
			FilePath: "testdata/gradle.war/WEB-INF/lib/log4j-1.2.17.jar",
		},
		{
			Name:     "org.apache.commons:commons-compress",
			Version:  "1.19",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-compress-1.19.jar",
		},
	}

	// manually created
	wantSHA1 = []ftypes.Package{
		{
			Name:     "org.springframework:spring-core",
			Version:  "5.3.3",
			FilePath: "testdata/test.jar",
		},
	}

	// offline
	wantOffline = []ftypes.Package{
		{
			Name:     "org.springframework:Spring Framework",
			Version:  "2.5.6.SEC03",
			FilePath: "testdata/test.jar",
		},
	}

	// manually created
	wantHeuristic = []ftypes.Package{
		{
			Name:     "com.example:heuristic",
			Version:  "1.0.0-SNAPSHOT",
			FilePath: "testdata/heuristic-1.0.0-SNAPSHOT.jar",
		},
	}

	// manually created
	wantFatjar = []ftypes.Package{
		{
			Name:     "com.google.guava:failureaccess",
			Version:  "1.0.1",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.guava:guava",
			Version:  "29.0-jre",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.guava:listenablefuture",
			Version:  "9999.0-empty-to-avoid-conflict-with-guava",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.j2objc:j2objc-annotations",
			Version:  "1.3",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "org.apache.hadoop.thirdparty:hadoop-shaded-guava",
			Version:  "1.1.0-SNAPSHOT",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
	}

	// manually created
	wantNestedJar = []ftypes.Package{
		{
			Name:     "test:nested",
			Version:  "0.0.1",
			FilePath: "testdata/nested.jar",
		},
		{
			Name:     "test:nested2",
			Version:  "0.0.2",
			FilePath: "testdata/nested.jar/META-INF/jars/nested2.jar",
		},
		{
			Name:     "test:nested3",
			Version:  "0.0.3",
			FilePath: "testdata/nested.jar/META-INF/jars/nested2.jar/META-INF/jars/nested3.jar",
		},
	}

	// Manually created.
	// Files of `io.quarkus.gizmo.gizmo-1.1.jar` (gizmo:1.1.0 (from sha1)):
	//├── bar
	//│   ├── bar
	//│   │   └── pom.properties (jackson-databind:2.13.4)
	//│   └── foo
	//│       └── pom.properties (jackson-databind:2.12.3)
	//├── foo
	//│   ├── bar
	//│   │   └── pom.properties (jackson-databind:2.12.3)
	//│   └── foo
	//│       └── pom.properties (jackson-databind:2.13.4)
	//├── jars
	//│   ├── log4j-1.2.16.jar (log4j:1.2.16)
	//│   └── log4j-1.2.17.jar (log4j:1.2.17)
	//└── META-INF
	//    ├── INDEX.LIST
	//    ├── MANIFEST.MF
	//    └── maven
	//        └── io.quarkus.gizmo
	//            └── gizmo
	//                ├── pom.properties (gizmo:1.1)
	//                └── pom.xml
	wantDuplicatesJar = []ftypes.Package{
		{
			Name:     "io.quarkus.gizmo:gizmo",
			Version:  "1.1",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.16",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar/jars/log4j-1.2.16.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.17",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar/jars/log4j-1.2.17.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.12.3",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.13.4",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
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
	VersionCount int    `json:"versionCount"`
}

func TestParse(t *testing.T) {
	vectors := []struct {
		name    string
		file    string // Test input file
		offline bool
		want    []ftypes.Package
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
			name: "nested jars",
			file: "testdata/nested.jar",
			want: wantNestedJar,
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
		{
			name: "duplicate libraries",
			file: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
			want: wantDuplicatesJar,
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
		case strings.Contains(r.URL.Query().Get("q"), "Gizmo"):
			res.Response.NumFound = 0
		case strings.Contains(r.URL.Query().Get("q"), "1c78bbc4d8c58b9af8eee82b84f2c26ec48e9a2b"):
			res.Response.Docs = []doc{
				{
					ID:         "io.quarkus.gizmo.gizmo",
					GroupID:    "io.quarkus.gizmo",
					ArtifactID: "gizmo",
					Version:    "1.1.0",
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

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)
		})
	}
}
