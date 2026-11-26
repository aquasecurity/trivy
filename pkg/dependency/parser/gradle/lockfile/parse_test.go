package lockfile

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lockfile",
			want: []ftypes.Package{
				{
					ID:      "cglib:cglib-nodep:2.1.2",
					Name:    "cglib:cglib-nodep",
					Version: "2.1.2",
					Dev:     false,
					Locations: []ftypes.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
				{
					ID:      "junit:junit:4.13.2",
					Name:    "junit:junit",
					Version: "4.13.2",
					Dev:     true,
					Locations: []ftypes.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					ID:      "org.springframework:spring-asm:3.1.3.RELEASE",
					Name:    "org.springframework:spring-asm",
					Version: "3.1.3.RELEASE",
					Dev:     false,
					Locations: []ftypes.Location{
						{
							StartLine: 6,
							EndLine:   6,
						},
					},
				},
				{
					ID:      "org.springframework:spring-beans:5.0.5.RELEASE",
					Name:    "org.springframework:spring-beans",
					Version: "5.0.5.RELEASE",
					Dev:     false,
					Locations: []ftypes.Location{
						{
							StartLine: 7,
							EndLine:   7,
						},
					},
				},
			},
		},
		{
			name:      "android test configurations",
			inputFile: "testdata/android.lockfile",
			want: []ftypes.Package{
				{
					ID:      "androidx.test.ext:junit:1.1.5",
					Name:    "androidx.test.ext:junit",
					Version: "1.1.5",
					Dev:     true,
					Locations: []ftypes.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					ID:      "junit:junit:4.12",
					Name:    "junit:junit",
					Version: "4.12",
					Dev:     true,
					Locations: []ftypes.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
				{
					ID:      "org.mockito:mockito-core:5.11.0",
					Name:    "org.mockito:mockito-core",
					Version: "5.11.0",
					Dev:     false,
					Locations: []ftypes.Location{
						{
							StartLine: 6,
							EndLine:   6,
						},
					},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.lockfile",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			pkgs, _, _ := parser.Parse(t.Context(), f)
			sort.Sort(ftypes.Packages(pkgs))
			assert.Equal(t, tt.want, pkgs)
		})
	}
}

func TestIsTestConfiguration(t *testing.T) {
	tests := []struct {
		configuration string
		want          bool
	}{
		// JVM test configurations
		{configuration: "testCompileClasspath", want: true},
		{configuration: "testRuntimeClasspath", want: true},
		// Android test configurations (build variant prefix)
		{configuration: "debugUnitTestCompileClasspath", want: true},
		{configuration: "debugUnitTestRuntimeClasspath", want: true},
		{configuration: "releaseUnitTestRuntimeClasspath", want: true},
		{configuration: "debugAndroidTestCompileClasspath", want: true},
		{configuration: "freeReleaseAndroidTestRuntimeClasspath", want: true},
		{configuration: "debugUnitTestAnnotationProcessorClasspath", want: true},
		// Production configurations must never be treated as test configurations
		{configuration: "compileClasspath", want: false},
		{configuration: "runtimeClasspath", want: false},
		{configuration: "releaseRuntimeClasspath", want: false},
		{configuration: "classpath", want: false},
		{configuration: "", want: false},
		// Near misses: no variant prefix, or only a partial Android suffix
		{configuration: "UnitTestCompileClasspath", want: false},
		{configuration: "AndroidTestRuntimeClasspath", want: false},
		{configuration: "debugUnitTestClasspath", want: false},
		{configuration: "debugUnitTestRuntimeClasspathExtra", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.configuration, func(t *testing.T) {
			assert.Equal(t, tt.want, isTestConfiguration(tt.configuration))
		})
	}
}
