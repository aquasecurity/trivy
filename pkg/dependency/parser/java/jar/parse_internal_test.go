package jar_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
)

func TestEmbeddedPomGAV(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantGroup string
		wantArt   string
		wantOK    bool
	}{
		{
			name:      "valid path",
			path:      "META-INF/maven/com.example/demo/pom.xml",
			wantGroup: "com.example",
			wantArt:   "demo",
			wantOK:    true,
		},
		{
			name:   "wrong prefix",
			path:   "BOOT-INF/classes/pom.xml",
			wantOK: false,
		},
		{
			name:   "not pom.xml",
			path:   "META-INF/maven/com.example/demo/pom.properties",
			wantOK: false,
		},
		{
			name:   "missing artifactId",
			path:   "META-INF/maven/com.example/pom.xml",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupID, artifactID, ok := jar.EmbeddedPomGAV(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantGroup, groupID)
			assert.Equal(t, tt.wantArt, artifactID)
		})
	}
}

func TestDecodePomLicenses(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want []string
	}{
		{
			name: "single license",
			xml:  `<project><licenses><license><name>Apache-2.0</name></license></licenses></project>`,
			want: []string{"Apache-2.0"},
		},
		{
			name: "multiple licenses",
			xml:  `<project><licenses><license><name>MIT</name></license><license><name>Apache-2.0</name></license></licenses></project>`,
			want: []string{"MIT", "Apache-2.0"},
		},
		{
			name: "name with surrounding whitespace",
			xml:  "<project><licenses><license><name>  Apache-2.0\n  </name></license></licenses></project>",
			want: []string{"Apache-2.0"},
		},
		{
			name: "empty name is skipped",
			xml:  `<project><licenses><license><name></name></license></licenses></project>`,
			want: nil,
		},
		{
			name: "no licenses block (parent only)",
			xml:  `<project><parent><groupId>com.example</groupId></parent></project>`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jar.DecodePomLicenses(strings.NewReader(tt.xml))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
