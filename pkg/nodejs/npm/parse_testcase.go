package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v1 && cd node_v1
	// npm init --force
	// npm install --save finalhandler@1.1.1 body-parser@1.18.3 ms@1.0.0
	// npm install --save-dev debug@2.5.2
	// npm i --lockfile-version 1
	// libraries are filled manually

	npmV1Libs = []types.Library{
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz"}}, Locations: []types.Location{{StartLine: 7, EndLine: 38}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz"}}, Locations: []types.Location{{StartLine: 39, EndLine: 43}}},
		{ID: "content-type@1.0.5", Name: "content-type", Version: "1.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz"}}, Locations: []types.Location{{StartLine: 44, EndLine: 48}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}, Locations: []types.Location{{StartLine: 24, EndLine: 31}, {StartLine: 100, EndLine: 107}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}, Locations: []types.Location{{StartLine: 66, EndLine: 70}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 71, EndLine: 75}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}, Locations: []types.Location{{StartLine: 76, EndLine: 80}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}, Locations: []types.Location{{StartLine: 81, EndLine: 85}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 86, EndLine: 114}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz"}}, Locations: []types.Location{{StartLine: 115, EndLine: 125}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz"}}, Locations: []types.Location{{StartLine: 126, EndLine: 133}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz"}}, Locations: []types.Location{{StartLine: 134, EndLine: 138}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz"}}, Locations: []types.Location{{StartLine: 139, EndLine: 143}}},
		{ID: "mime-db@1.52.0", Name: "mime-db", Version: "1.52.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz"}}, Locations: []types.Location{{StartLine: 144, EndLine: 148}}},
		{ID: "mime-types@2.1.35", Name: "mime-types", Version: "2.1.35", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz"}}, Locations: []types.Location{{StartLine: 149, EndLine: 156}}},
		{ID: "ms@1.0.0", Name: "ms", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 157, EndLine: 161}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}, Locations: []types.Location{{StartLine: 32, EndLine: 36}, {StartLine: 108, EndLine: 112}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}, Locations: []types.Location{{StartLine: 162, EndLine: 169}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz"}}, Locations: []types.Location{{StartLine: 170, EndLine: 174}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"}}, Locations: []types.Location{{StartLine: 175, EndLine: 179}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz"}}, Locations: []types.Location{{StartLine: 180, EndLine: 190}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz"}}, Locations: []types.Location{{StartLine: 191, EndLine: 195}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz"}}, Locations: []types.Location{{StartLine: 196, EndLine: 200}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz"}}, Locations: []types.Location{{StartLine: 201, EndLine: 205}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz"}}, Locations: []types.Location{{StartLine: 206, EndLine: 214}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 215, EndLine: 219}}},
	}

	// dependencies are filled manually
	npmDeps = []types.Dependency{
		{ID: "body-parser@1.18.3", DependsOn: []string{"bytes@3.0.0", "content-type@1.0.5", "debug@2.6.9", "depd@1.1.2", "http-errors@1.6.3", "iconv-lite@0.4.23", "on-finished@2.3.0", "qs@6.5.2", "raw-body@2.3.3", "type-is@1.6.18"}},
		{ID: "debug@2.6.9", DependsOn: []string{"ms@2.0.0"}},
		{ID: "finalhandler@1.1.1", DependsOn: []string{"debug@2.6.9", "encodeurl@1.0.2", "escape-html@1.0.3", "on-finished@2.3.0", "parseurl@1.3.3", "statuses@1.4.0", "unpipe@1.0.0"}},
		{ID: "http-errors@1.6.3", DependsOn: []string{"depd@1.1.2", "inherits@2.0.3", "setprototypeof@1.1.0", "statuses@1.4.0"}},
		{ID: "iconv-lite@0.4.23", DependsOn: []string{"safer-buffer@2.1.2"}},
		{ID: "mime-types@2.1.35", DependsOn: []string{"mime-db@1.52.0"}},
		{ID: "on-finished@2.3.0", DependsOn: []string{"ee-first@1.1.1"}},
		{ID: "raw-body@2.3.3", DependsOn: []string{"bytes@3.0.0", "http-errors@1.6.3", "iconv-lite@0.4.23", "unpipe@1.0.0"}},
		{ID: "type-is@1.6.18", DependsOn: []string{"media-typer@0.3.0", "mime-types@2.1.35"}},
	}

	// ... and
	// npm i --lockfile-version 2
	// same as npmV1Libs but change `Indirect` field to false for `body-parser@1.18.3`, `finalhandler@1.1.1` and `ms@1.0.0`  libraries.
	// also need to get locations from `packages` struct
	// --- lockfile version 3 ---
	// npm i --lockfile-version 3
	// same as npmV2Libs.
	npmV2Libs = []types.Library{
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz"}}, Locations: []types.Location{{StartLine: 20, EndLine: 39}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz"}}, Locations: []types.Location{{StartLine: 53, EndLine: 60}}},
		{ID: "content-type@1.0.5", Name: "content-type", Version: "1.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz"}}, Locations: []types.Location{{StartLine: 61, EndLine: 68}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}, Locations: []types.Location{{StartLine: 40, EndLine: 47}, {StartLine: 127, EndLine: 134}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}, Locations: []types.Location{{StartLine: 84, EndLine: 91}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 92, EndLine: 96}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}, Locations: []types.Location{{StartLine: 97, EndLine: 104}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}, Locations: []types.Location{{StartLine: 105, EndLine: 109}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 110, EndLine: 126}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz"}}, Locations: []types.Location{{StartLine: 140, EndLine: 153}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz"}}, Locations: []types.Location{{StartLine: 154, EndLine: 164}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz"}}, Locations: []types.Location{{StartLine: 165, EndLine: 169}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz"}}, Locations: []types.Location{{StartLine: 170, EndLine: 177}}},
		{ID: "mime-db@1.52.0", Name: "mime-db", Version: "1.52.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz"}}, Locations: []types.Location{{StartLine: 178, EndLine: 185}}},
		{ID: "mime-types@2.1.35", Name: "mime-types", Version: "2.1.35", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz"}}, Locations: []types.Location{{StartLine: 186, EndLine: 196}}},
		{ID: "ms@1.0.0", Name: "ms", Version: "1.0.0", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 197, EndLine: 201}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}, Locations: []types.Location{{StartLine: 48, EndLine: 52}, {StartLine: 135, EndLine: 139}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}, Locations: []types.Location{{StartLine: 202, EndLine: 212}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz"}}, Locations: []types.Location{{StartLine: 213, EndLine: 220}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"}}, Locations: []types.Location{{StartLine: 221, EndLine: 228}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz"}}, Locations: []types.Location{{StartLine: 229, EndLine: 242}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz"}}, Locations: []types.Location{{StartLine: 243, EndLine: 247}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz"}}, Locations: []types.Location{{StartLine: 248, EndLine: 252}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz"}}, Locations: []types.Location{{StartLine: 253, EndLine: 260}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz"}}, Locations: []types.Location{{StartLine: 261, EndLine: 272}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 273, EndLine: 280}}},
	}
)
