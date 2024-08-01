package yarn

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParsePattern(t *testing.T) {
	vectors := []struct {
		name           string
		target         string
		expectName     string
		expectProtocol string
		expactVersion  string
		occurErr       bool
	}{
		{
			name:          "normal",
			target:        `asn1@~0.2.3:`,
			expectName:    "asn1",
			expactVersion: "~0.2.3",
		},
		{
			name:           "normal with protocol",
			target:         `asn1@npm:~0.2.3:`,
			expectName:     "asn1",
			expectProtocol: "npm",
			expactVersion:  "~0.2.3",
		},
		{
			name:          "scope",
			target:        `@babel/code-frame@^7.0.0:`,
			expectName:    "@babel/code-frame",
			expactVersion: "^7.0.0",
		},
		{
			name:           "scope with protocol",
			target:         `@babel/code-frame@npm:^7.0.0:`,
			expectName:     "@babel/code-frame",
			expectProtocol: "npm",
			expactVersion:  "^7.0.0",
		},
		{
			name:           "scope with protocol and quotes",
			target:         `"@babel/code-frame@npm:^7.0.0":`,
			expectName:     "@babel/code-frame",
			expectProtocol: "npm",
			expactVersion:  "^7.0.0",
		},
		{
			name:          "unusual version",
			target:        `grunt-contrib-cssmin@3.0.*:`,
			expectName:    "grunt-contrib-cssmin",
			expactVersion: "3.0.*",
		},
		{
			name:          "conditional version",
			target:        `"js-tokens@^3.0.0 || ^4.0.0":`,
			expectName:    "js-tokens",
			expactVersion: "^3.0.0 || ^4.0.0",
		},
		{
			target:        "grunt-contrib-uglify-es@gruntjs/grunt-contrib-uglify#harmony:",
			expectName:    "grunt-contrib-uglify-es",
			expactVersion: "gruntjs/grunt-contrib-uglify#harmony",
		},
		{
			target:         `"jquery@git+https://xxxx:x-oauth-basic@github.com/tomoyamachi/jquery":`,
			expectName:     "jquery",
			expectProtocol: "git+https",
			expactVersion:  "//xxxx:x-oauth-basic@github.com/tomoyamachi/jquery",
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		gotName, gotProtocol, gotVersion, err := parsePattern(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target :%s", gotName, v.expectName, v.target)
		}

		if gotProtocol != v.expectProtocol {
			t.Errorf("protocol mismatch: got %s, want %s, target :%s", gotProtocol, v.expectProtocol, v.target)
		}

		if gotVersion != v.expactVersion {
			t.Errorf("version mismatch: got %s, want %s, target :%s", gotVersion, v.expactVersion, v.target)
		}
	}
}

func TestParsePackagePatterns(t *testing.T) {
	vectors := []struct {
		name           string
		target         string
		expectName     string
		expectProtocol string
		expactPatterns []string
		occurErr       bool
	}{
		{
			name:       "normal",
			target:     `asn1@~0.2.3:`,
			expectName: "asn1",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:       "normal with quotes",
			target:     `"asn1@~0.2.3":`,
			expectName: "asn1",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:           "normal with protocol",
			target:         `asn1@npm:~0.2.3:`,
			expectName:     "asn1",
			expectProtocol: "npm",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:       "multiple patterns",
			target:     `loose-envify@^1.1.0, loose-envify@^1.4.0:`,
			expectName: "loose-envify",
			expactPatterns: []string{
				"loose-envify@^1.1.0",
				"loose-envify@^1.4.0",
			},
		},
		{
			name:           "multiple patterns v2",
			target:         `"loose-envify@npm:^1.1.0, loose-envify@npm:^1.4.0":`,
			expectName:     "loose-envify",
			expectProtocol: "npm",
			expactPatterns: []string{
				"loose-envify@^1.1.0",
				"loose-envify@^1.4.0",
			},
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		gotName, gotProtocol, gotPatterns, err := parsePackagePatterns(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target: %s", gotName, v.expectName, v.target)
		}

		if gotProtocol != v.expectProtocol {
			t.Errorf("protocol mismatch: got %s, want %s, target: %s", gotProtocol, v.expectProtocol, v.target)
		}

		sort.Strings(gotPatterns)
		sort.Strings(v.expactPatterns)

		assert.Equal(t, v.expactPatterns, gotPatterns)
	}
}

func TestGetDependency(t *testing.T) {
	vectors := []struct {
		name          string
		target        string
		expectName    string
		expactVersion string
		occurErr      bool
	}{
		{
			name:          "normal",
			target:        `    chalk "^2.0.1"`,
			expectName:    "chalk",
			expactVersion: "^2.0.1",
		},
		{
			name:          "range",
			target:        `    js-tokens "^3.0.0 || ^4.0.0"`,
			expectName:    "js-tokens",
			expactVersion: "^3.0.0 || ^4.0.0",
		},
		{
			name:          "normal v2",
			target:        `    depd: ~1.1.2`,
			expectName:    "depd",
			expactVersion: "~1.1.2",
		},
		{
			name:          "range version v2",
			target:        `    statuses: ">= 1.5.0 < 2"`,
			expectName:    "statuses",
			expactVersion: ">= 1.5.0 < 2",
		},
		{
			name:          "name with scope",
			target:        `    "@types/color-name": ^1.1.1`,
			expectName:    "@types/color-name",
			expactVersion: "^1.1.1",
		},
		{
			name:          "version with protocol",
			target:        `    ms: "npm:2.1.2"`,
			expectName:    "ms",
			expactVersion: "2.1.2",
		},
	}

	for _, v := range vectors {
		gotName, gotVersion, err := getDependency(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target: %s", gotName, v.expectName, v.target)
		}

		if gotVersion != v.expactVersion {
			t.Errorf("version mismatch: got %s, want %s, target: %s", gotVersion, v.expactVersion, v.target)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []ftypes.Package
		wantDeps []ftypes.Dependency
	}{
		{
			name:     "happy",
			file:     "testdata/yarn_happy.lock",
			want:     yarnHappy,
			wantDeps: yarnHappyDeps,
		},
		{
			file: "testdata/yarn_with_npm.lock",
			want: yarnWithNpm,
		},
		{
			name:     "happy v2",
			file:     "testdata/yarn_v2_happy.lock",
			want:     yarnV2Happy,
			wantDeps: yarnV2HappyDeps,
		},
		{
			name:     "yarn with local dependency",
			file:     "testdata/yarn_with_local.lock",
			want:     yarnWithLocal,
			wantDeps: yarnWithLocalDeps,
		},
		{
			name:     "yarn v2 with protocols in dependency section",
			file:     "testdata/yarn_v2_deps_with_protocol.lock",
			want:     yarnV2DepsWithProtocol,
			wantDeps: yarnV2DepsWithProtocolDeps,
		},
		{
			name: "yarn with git dependency",
			file: "testdata/yarn_with_git.lock",
		},
		{
			name: "yarn file with bad protocol",
			file: "testdata/yarn_with_bad_protocol.lock",
			want: yarnBadProtocol,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)

			if tt.wantDeps != nil {
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}
