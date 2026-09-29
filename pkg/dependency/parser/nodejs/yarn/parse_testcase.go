package yarn

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	yarnHappy = []ftypes.Package{
		{ID: "@babel/helper-regex@7.4.4", Name: "@babel/helper-regex", Version: "7.4.4", Locations: []ftypes.Location{{StartLine: 4, EndLine: 9}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []ftypes.Location{{StartLine: 11, EndLine: 14}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []ftypes.Location{{StartLine: 16, EndLine: 19}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []ftypes.Location{{StartLine: 21, EndLine: 24}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Locations: []ftypes.Location{{StartLine: 26, EndLine: 29}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []ftypes.Location{{StartLine: 31, EndLine: 34}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []ftypes.Location{{StartLine: 41, EndLine: 44}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []ftypes.Location{{StartLine: 36, EndLine: 39}}},
		{ID: "lodash@4.17.11", Name: "lodash", Version: "4.17.11", Locations: []ftypes.Location{{StartLine: 46, EndLine: 49}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []ftypes.Location{{StartLine: 51, EndLine: 56}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Locations: []ftypes.Location{{StartLine: 58, EndLine: 61}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Locations: []ftypes.Location{{StartLine: 63, EndLine: 66}}},
		{ID: "statuses@1.5.0", Name: "statuses", Version: "1.5.0", Locations: []ftypes.Location{{StartLine: 68, EndLine: 71}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []ftypes.Location{{StartLine: 73, EndLine: 79}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []ftypes.Location{{StartLine: 82, EndLine: 87}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []ftypes.Location{{StartLine: 89, EndLine: 94}}},
		{ID: "whatwg-fetch@3.0.0", Name: "whatwg-fetch", Version: "3.0.0", Locations: []ftypes.Location{{StartLine: 96, EndLine: 99}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []ftypes.Location{{StartLine: 101, EndLine: 106}}},
	}

	yarnHappyDeps = []ftypes.Dependency{
		{
			ID: "@babel/helper-regex@7.4.4",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
	}

	yarnV2Happy = []ftypes.Package{
		{ID: "@types/color-name@1.1.1", Name: "@types/color-name", Version: "1.1.1", Locations: []ftypes.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "abbrev@1.1.1", Name: "abbrev", Version: "1.1.1", Locations: []ftypes.Location{{StartLine: 15, EndLine: 20}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []ftypes.Location{{StartLine: 22, EndLine: 29}}},
		{ID: "ansi-styles@4.2.1", Name: "ansi-styles", Version: "4.2.1", Locations: []ftypes.Location{{StartLine: 31, EndLine: 39}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Locations: []ftypes.Location{{StartLine: 41, EndLine: 46}}},
		{ID: "async@3.2.0", Name: "async", Version: "3.2.0", Locations: []ftypes.Location{{StartLine: 48, EndLine: 53}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []ftypes.Location{{StartLine: 63, EndLine: 70}}},
		{ID: "color-convert@2.0.1", Name: "color-convert", Version: "2.0.1", Locations: []ftypes.Location{{StartLine: 72, EndLine: 79}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []ftypes.Location{{StartLine: 81, EndLine: 86}}},
		{ID: "color-name@1.1.4", Name: "color-name", Version: "1.1.4", Locations: []ftypes.Location{{StartLine: 88, EndLine: 93}}},
		{ID: "ipaddr.js@1.9.1", Name: "ipaddr.js", Version: "1.9.1", Locations: []ftypes.Location{{StartLine: 104, EndLine: 109}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []ftypes.Location{{StartLine: 111, EndLine: 116}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []ftypes.Location{{StartLine: 118, EndLine: 127}}},
		{ID: "node-gyp@7.1.0", Name: "node-gyp", Version: "7.1.0", Locations: []ftypes.Location{{StartLine: 129, EndLine: 136}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []ftypes.Location{{StartLine: 138, EndLine: 145}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []ftypes.Location{{StartLine: 147, EndLine: 152}}},
	}

	yarnV2HappyDeps = []ftypes.Dependency{
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "ansi-styles@4.2.1",
			DependsOn: []string{
				"@types/color-name@1.1.1",
				"color-convert@2.0.1",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "color-convert@2.0.1",
			DependsOn: []string{
				"color-name@1.1.4",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
	}

	yarnWithLocal = []ftypes.Package{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []ftypes.Location{{StartLine: 5, EndLine: 8}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []ftypes.Location{{StartLine: 10, EndLine: 13}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []ftypes.Location{{StartLine: 15, EndLine: 20}}},
	}

	yarnWithLocalDeps = []ftypes.Dependency{
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
	}

	yarnWithNpm = []ftypes.Package{
		{ID: "jquery@3.6.0", Name: "jquery", Version: "3.6.0", Locations: []ftypes.Location{{StartLine: 1, EndLine: 4}}},
	}

	yarnBadProtocol = []ftypes.Package{
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []ftypes.Location{{StartLine: 4, EndLine: 7}}},
	}

	yarnV2DepsWithProtocol = []ftypes.Package{
		{ID: "debug@4.3.4", Name: "debug", Version: "4.3.4", Locations: []ftypes.Location{{StartLine: 16, EndLine: 26}}},
		{ID: "ms@2.1.2", Name: "ms", Version: "2.1.2", Locations: []ftypes.Location{{StartLine: 28, EndLine: 33}}},
	}

	yarnV2DepsWithProtocolDeps = []ftypes.Dependency{
		{
			ID:        "debug@4.3.4",
			DependsOn: []string{"ms@2.1.2"},
		},
	}
)
