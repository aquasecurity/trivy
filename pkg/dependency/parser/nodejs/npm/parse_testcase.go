package npm

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v1 && cd node_v1
	// npm init --force
	// npm install --save finalhandler@1.1.1 body-parser@1.18.3 ms@1.0.0 @babel/helper-string-parser@7.19.4
	// npm install --save-dev debug@2.5.2
	// npm install --save-optional promise
	// npm i --lockfile-version 1
	// libraries are filled manually

	npmV1Libs = []types.Library{
		{
			ID:       "@babel/helper-string-parser@7.19.4",
			Name:     "@babel/helper-string-parser",
			Version:  "7.19.4",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 7,
					EndLine:   11,
				},
			},
		},
		{
			ID:       "asap@2.0.6",
			Name:     "asap",
			Version:  "2.0.6",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 12,
					EndLine:   17,
				},
			},
		},
		{
			ID:       "body-parser@1.18.3",
			Name:     "body-parser",
			Version:  "1.18.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 18,
					EndLine:   49,
				},
			},
		},
		{
			ID:       "bytes@3.0.0",
			Name:     "bytes",
			Version:  "3.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 50,
					EndLine:   54,
				},
			},
		},
		{
			ID:       "content-type@1.0.5",
			Name:     "content-type",
			Version:  "1.0.5",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 55,
					EndLine:   59,
				},
			},
		},
		{
			ID:       "debug@2.5.2",
			Name:     "debug",
			Version:  "2.5.2",
			Dev:      true,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 60,
					EndLine:   76,
				},
			},
		},
		{
			ID:       "debug@2.6.9",
			Name:     "debug",
			Version:  "2.6.9",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 35,
					EndLine:   42,
				},
				{
					StartLine: 111,
					EndLine:   118,
				},
			},
		},
		{
			ID:       "depd@1.1.2",
			Name:     "depd",
			Version:  "1.1.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 77,
					EndLine:   81,
				},
			},
		},
		{
			ID:       "ee-first@1.1.1",
			Name:     "ee-first",
			Version:  "1.1.1",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 82,
					EndLine:   86,
				},
			},
		},
		{
			ID:       "encodeurl@1.0.2",
			Name:     "encodeurl",
			Version:  "1.0.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 87,
					EndLine:   91,
				},
			},
		},
		{
			ID:       "escape-html@1.0.3",
			Name:     "escape-html",
			Version:  "1.0.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 92,
					EndLine:   96,
				},
			},
		},
		{
			ID:       "finalhandler@1.1.1",
			Name:     "finalhandler",
			Version:  "1.1.1",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 97,
					EndLine:   125,
				},
			},
		},
		{
			ID:       "http-errors@1.6.3",
			Name:     "http-errors",
			Version:  "1.6.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 126,
					EndLine:   136,
				},
			},
		},
		{
			ID:       "iconv-lite@0.4.23",
			Name:     "iconv-lite",
			Version:  "0.4.23",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 137,
					EndLine:   144,
				},
			},
		},
		{
			ID:       "inherits@2.0.3",
			Name:     "inherits",
			Version:  "2.0.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 145,
					EndLine:   149,
				},
			},
		},
		{
			ID:       "media-typer@0.3.0",
			Name:     "media-typer",
			Version:  "0.3.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 150,
					EndLine:   154,
				},
			},
		},
		{
			ID:       "mime-db@1.52.0",
			Name:     "mime-db",
			Version:  "1.52.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 155,
					EndLine:   159,
				},
			},
		},
		{
			ID:       "mime-types@2.1.35",
			Name:     "mime-types",
			Version:  "2.1.35",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 160,
					EndLine:   167,
				},
			},
		},
		{
			ID:       "ms@0.7.2",
			Name:     "ms",
			Version:  "0.7.2",
			Dev:      true,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 69,
					EndLine:   74,
				},
			},
		},
		{
			ID:       "ms@1.0.0",
			Name:     "ms",
			Version:  "1.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 168,
					EndLine:   172,
				},
			},
		},
		{
			ID:       "ms@2.0.0",
			Name:     "ms",
			Version:  "2.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 43,
					EndLine:   47,
				},
				{
					StartLine: 119,
					EndLine:   123,
				},
			},
		},
		{
			ID:       "on-finished@2.3.0",
			Name:     "on-finished",
			Version:  "2.3.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 173,
					EndLine:   180,
				},
			},
		},
		{
			ID:       "parseurl@1.3.3",
			Name:     "parseurl",
			Version:  "1.3.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 181,
					EndLine:   185,
				},
			},
		},
		{
			ID:       "promise@8.3.0",
			Name:     "promise",
			Version:  "8.3.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/promise/-/promise-8.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 186,
					EndLine:   194,
				},
			},
		},
		{
			ID:       "qs@6.5.2",
			Name:     "qs",
			Version:  "6.5.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 195,
					EndLine:   199,
				},
			},
		},
		{
			ID:       "raw-body@2.3.3",
			Name:     "raw-body",
			Version:  "2.3.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 200,
					EndLine:   210,
				},
			},
		},
		{
			ID:       "safer-buffer@2.1.2",
			Name:     "safer-buffer",
			Version:  "2.1.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 211,
					EndLine:   215,
				},
			},
		},
		{
			ID:       "setprototypeof@1.1.0",
			Name:     "setprototypeof",
			Version:  "1.1.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 216,
					EndLine:   220,
				},
			},
		},
		{
			ID:       "statuses@1.4.0",
			Name:     "statuses",
			Version:  "1.4.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 221,
					EndLine:   225,
				},
			},
		},
		{
			ID:       "type-is@1.6.18",
			Name:     "type-is",
			Version:  "1.6.18",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 226,
					EndLine:   234,
				},
			},
		},
		{
			ID:       "unpipe@1.0.0",
			Name:     "unpipe",
			Version:  "1.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 235,
					EndLine:   239,
				},
			},
		},
	}

	// dependencies are filled manually
	npmDeps = []types.Dependency{
		{
			ID: "body-parser@1.18.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"content-type@1.0.5",
				"debug@2.6.9",
				"depd@1.1.2",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"on-finished@2.3.0",
				"qs@6.5.2",
				"raw-body@2.3.3",
				"type-is@1.6.18",
			},
		},
		{
			ID:        "debug@2.5.2",
			DependsOn: []string{"ms@0.7.2"},
		},
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID: "finalhandler@1.1.1",
			DependsOn: []string{
				"debug@2.6.9",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"statuses@1.4.0",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "http-errors@1.6.3",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.3",
				"setprototypeof@1.1.0",
				"statuses@1.4.0",
			},
		},
		{
			ID:        "iconv-lite@0.4.23",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "mime-types@2.1.35",
			DependsOn: []string{"mime-db@1.52.0"},
		},
		{
			ID:        "on-finished@2.3.0",
			DependsOn: []string{"ee-first@1.1.1"},
		},
		{
			ID:        "promise@8.3.0",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID: "raw-body@2.3.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "type-is@1.6.18",
			DependsOn: []string{
				"media-typer@0.3.0",
				"mime-types@2.1.35",
			},
		},
	}

	// ... and
	// npm i --lockfile-version 2
	// same as npmV1Libs but change `Indirect` field to false for `body-parser@1.18.3`, `finalhandler@1.1.1`, `@babel/helper-string-parser@7.19.4`, `promise@8.3.0` and `ms@1.0.0`  libraries.
	// also need to get locations from `packages` struct
	// --- lockfile version 3 ---
	// npm i --lockfile-version 3
	// same as npmV2Libs.
	npmV2Libs = []types.Library{
		{
			ID:       "@babel/helper-string-parser@7.19.4",
			Name:     "@babel/helper-string-parser",
			Version:  "7.19.4",
			Dev:      false,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 24,
					EndLine:   31,
				},
			},
		},
		{
			ID:       "asap@2.0.6",
			Name:     "asap",
			Version:  "2.0.6",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 32,
					EndLine:   37,
				},
			},
		},
		{
			ID:       "body-parser@1.18.3",
			Name:     "body-parser",
			Version:  "1.18.3",
			Dev:      false,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 38,
					EndLine:   57,
				},
			},
		},
		{
			ID:       "bytes@3.0.0",
			Name:     "bytes",
			Version:  "3.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 71,
					EndLine:   78,
				},
			},
		},
		{
			ID:       "content-type@1.0.5",
			Name:     "content-type",
			Version:  "1.0.5",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 79,
					EndLine:   86,
				},
			},
		},
		{
			ID:       "debug@2.5.2",
			Name:     "debug",
			Version:  "2.5.2",
			Dev:      true,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 87,
					EndLine:   95,
				},
			},
		},
		{
			ID:       "debug@2.6.9",
			Name:     "debug",
			Version:  "2.6.9",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 58,
					EndLine:   65,
				},
				{
					StartLine: 145,
					EndLine:   152,
				},
			},
		},
		{
			ID:       "depd@1.1.2",
			Name:     "depd",
			Version:  "1.1.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 102,
					EndLine:   109,
				},
			},
		},
		{
			ID:       "ee-first@1.1.1",
			Name:     "ee-first",
			Version:  "1.1.1",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 110,
					EndLine:   114,
				},
			},
		},
		{
			ID:       "encodeurl@1.0.2",
			Name:     "encodeurl",
			Version:  "1.0.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 115,
					EndLine:   122,
				},
			},
		},
		{
			ID:       "escape-html@1.0.3",
			Name:     "escape-html",
			Version:  "1.0.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 123,
					EndLine:   127,
				},
			},
		},
		{
			ID:       "finalhandler@1.1.1",
			Name:     "finalhandler",
			Version:  "1.1.1",
			Dev:      false,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 128,
					EndLine:   144,
				},
			},
		},
		{
			ID:       "http-errors@1.6.3",
			Name:     "http-errors",
			Version:  "1.6.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 158,
					EndLine:   171,
				},
			},
		},
		{
			ID:       "iconv-lite@0.4.23",
			Name:     "iconv-lite",
			Version:  "0.4.23",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 172,
					EndLine:   182,
				},
			},
		},
		{
			ID:       "inherits@2.0.3",
			Name:     "inherits",
			Version:  "2.0.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 183,
					EndLine:   187,
				},
			},
		},
		{
			ID:       "media-typer@0.3.0",
			Name:     "media-typer",
			Version:  "0.3.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 188,
					EndLine:   195,
				},
			},
		},
		{
			ID:       "mime-db@1.52.0",
			Name:     "mime-db",
			Version:  "1.52.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 196,
					EndLine:   203,
				},
			},
		},
		{
			ID:       "mime-types@2.1.35",
			Name:     "mime-types",
			Version:  "2.1.35",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 204,
					EndLine:   214,
				},
			},
		},
		{
			ID:       "ms@0.7.2",
			Name:     "ms",
			Version:  "0.7.2",
			Dev:      true,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 96,
					EndLine:   101,
				},
			},
		},
		{
			ID:       "ms@1.0.0",
			Name:     "ms",
			Version:  "1.0.0",
			Dev:      false,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 215,
					EndLine:   219,
				},
			},
		},
		{
			ID:       "ms@2.0.0",
			Name:     "ms",
			Version:  "2.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 66,
					EndLine:   70,
				},
				{
					StartLine: 153,
					EndLine:   157,
				},
			},
		},
		{
			ID:       "on-finished@2.3.0",
			Name:     "on-finished",
			Version:  "2.3.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 220,
					EndLine:   230,
				},
			},
		},
		{
			ID:       "parseurl@1.3.3",
			Name:     "parseurl",
			Version:  "1.3.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 231,
					EndLine:   238,
				},
			},
		},
		{
			ID:       "promise@8.3.0",
			Name:     "promise",
			Version:  "8.3.0",
			Dev:      false,
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/promise/-/promise-8.3.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 239,
					EndLine:   247,
				},
			},
		},
		{
			ID:       "qs@6.5.2",
			Name:     "qs",
			Version:  "6.5.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 248,
					EndLine:   255,
				},
			},
		},
		{
			ID:       "raw-body@2.3.3",
			Name:     "raw-body",
			Version:  "2.3.3",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 256,
					EndLine:   269,
				},
			},
		},
		{
			ID:       "safer-buffer@2.1.2",
			Name:     "safer-buffer",
			Version:  "2.1.2",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 270,
					EndLine:   274,
				},
			},
		},
		{
			ID:       "setprototypeof@1.1.0",
			Name:     "setprototypeof",
			Version:  "1.1.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 275,
					EndLine:   279,
				},
			},
		},
		{
			ID:       "statuses@1.4.0",
			Name:     "statuses",
			Version:  "1.4.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 280,
					EndLine:   287,
				},
			},
		},
		{
			ID:       "type-is@1.6.18",
			Name:     "type-is",
			Version:  "1.6.18",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 288,
					EndLine:   299,
				},
			},
		},
		{
			ID:       "unpipe@1.0.0",
			Name:     "unpipe",
			Version:  "1.0.0",
			Dev:      false,
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 300,
					EndLine:   307,
				},
			},
		},
	}

	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v3_with_workspace && cd node_v3_with_workspace
	// npm init --force
	// npm init -w ./functions/func1 !!! use `function1` name for package
	// grep -v "version" ./functions/func1/package.json > tmpfile && mv tmpfile ./functions/func1/package.json
	// npm init -w ./functions/nested_func --force
	// npm install --save debug@2.5.2
	// sed -i 's/\^/=/g' package.json
	// npm install --save debug@2.6.9 -w nested_func
	// npm install nested_func -w function1
	// grep -v "functions/func1" ./package.json > tmpfile && mv tmpfile ./package.json
	// sed -i 's/functions\/nested_func/functions\/*/g' package.json
	// npm update
	// libraries are filled manually
	npmV3WithWorkspaceLibs = []types.Library{
		{
			ID:       "debug@2.5.2",
			Name:     "debug",
			Version:  "2.5.2",
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.5.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 39,
					EndLine:   46,
				},
			},
		},
		{
			ID:       "debug@2.6.9",
			Name:     "debug",
			Version:  "2.6.9",
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 31,
					EndLine:   38,
				},
			},
		},
		{
			ID:       "function1",
			Name:     "function1",
			Version:  "",
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "functions/func1",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 18,
					EndLine:   23,
				},
			},
		},
		{
			ID:       "ms@0.7.2",
			Name:     "ms",
			Version:  "0.7.2",
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-0.7.2.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 47,
					EndLine:   51,
				},
			},
		},
		{
			ID:       "ms@2.0.0",
			Name:     "ms",
			Version:  "2.0.0",
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 56,
					EndLine:   60,
				},
			},
		},
		{
			ID:       "nested_func@1.0.0",
			Name:     "nested_func",
			Version:  "1.0.0",
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "functions/nested_func",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 24,
					EndLine:   30,
				},
			},
		},
	}

	npmV3WithWorkspaceDeps = []types.Dependency{
		{
			ID:        "debug@2.5.2",
			DependsOn: []string{"ms@0.7.2"},
		},
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID:        "function1",
			DependsOn: []string{"nested_func@1.0.0"},
		},
		{
			ID:        "nested_func@1.0.0",
			DependsOn: []string{"debug@2.6.9"},
		},
	}

	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v3_without_direct_deps && cd node_v3_without_direct_deps
	// npm init --force
	// npm init -w ./functions/func1 --force
	// npm install --save debug@2.6.9 -w func1
	// libraries are filled manually
	npmV3WithoutRootDepsField = []types.Library{
		{
			ID:       "debug@2.6.9",
			Name:     "debug",
			Version:  "2.6.9",
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 22,
					EndLine:   29,
				},
			},
		},
		{
			ID:       "func1@1.0.0",
			Name:     "func1",
			Version:  "1.0.0",
			Indirect: false,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "functions/func1",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 15,
					EndLine:   21,
				},
			},
		},
		{
			ID:       "ms@2.0.0",
			Name:     "ms",
			Version:  "2.0.0",
			Indirect: true,
			ExternalReferences: []types.ExternalRef{
				{
					Type: types.RefOther,
					URL:  "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
				},
			},
			Locations: []types.Location{
				{
					StartLine: 34,
					EndLine:   38,
				},
			},
		},
	}

	npmV3WithoutRootDepsFieldDeps = []types.Dependency{
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID:        "func1@1.0.0",
			DependsOn: []string{"debug@2.6.9"},
		},
	}
)
