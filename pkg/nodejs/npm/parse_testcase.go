package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\", \"\"},\n")}'
	npmNormal = []types.Library{
		{ID: "asap@2.0.7", Name: "asap", Version: "2.0.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asap/-/asap-2.0.7.tgz"}}},
		{ID: "jquery@3.4.0", Name: "jquery", Version: "3.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jquery/-/jquery-3.4.0.tgz"}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/promise/-/promise-8.0.3.tgz"}}},
	}

	npmNormalDeps = []types.Dependency{
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.7"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\", \"\"},\n")}'
	npmReact = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz"}}},
		{ID: "jquery@3.4.0", Name: "jquery", Version: "3.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jquery/-/jquery-3.4.0.tgz"}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz"}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz"}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz"}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/promise/-/promise-8.0.3.tgz"}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/prop-types/-/prop-types-15.7.2.tgz"}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react/-/react-16.8.6.tgz"}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react-is/-/react-is-16.8.6.tgz"}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/redux/-/redux-4.0.1.tgz"}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/scheduler/-/scheduler-0.13.6.tgz"}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/symbol-observable/-/symbol-observable-1.2.0.tgz"}}},
	}
	npmReactDeps = []types.Dependency{
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\", \"\"},\n")}'
	npmWithDev = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz"}}},
		{ID: "jquery@3.4.0", Name: "jquery", Version: "3.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jquery/-/jquery-3.4.0.tgz"}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz"}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz"}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz"}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/promise/-/promise-8.0.3.tgz"}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/prop-types/-/prop-types-15.7.2.tgz"}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react/-/react-16.8.6.tgz"}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react-is/-/react-is-16.8.6.tgz"}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/redux/-/redux-4.0.1.tgz"}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/scheduler/-/scheduler-0.13.6.tgz"}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/symbol-observable/-/symbol-observable-1.2.0.tgz"}}},
	}

	npmWithDevDeps = []types.Dependency{
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm install --save lodash request chalk commander express async axios vue
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\", \"\"},\n")}'
	npmMany = []types.Library{
		{ID: "accepts@1.3.6", Name: "accepts", Version: "1.3.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/accepts/-/accepts-1.3.6.tgz"}}},
		{ID: "ajv@6.10.0", Name: "ajv", Version: "6.10.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ajv/-/ajv-6.10.0.tgz"}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ansi-styles/-/ansi-styles-3.2.1.tgz"}}},
		{ID: "array-flatten@1.1.1", Name: "array-flatten", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/array-flatten/-/array-flatten-1.1.1.tgz"}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asap/-/asap-2.0.6.tgz"}}},
		{ID: "asn1@0.2.4", Name: "asn1", Version: "0.2.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asn1/-/asn1-0.2.4.tgz"}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/assert-plus/-/assert-plus-1.0.0.tgz"}}},
		{ID: "async@2.6.2", Name: "async", Version: "2.6.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/async/-/async-2.6.2.tgz"}}},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asynckit/-/asynckit-0.4.0.tgz"}}},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/aws-sign2/-/aws-sign2-0.7.0.tgz"}}},
		{ID: "aws4@1.8.0", Name: "aws4", Version: "1.8.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/aws4/-/aws4-1.8.0.tgz"}}},
		{ID: "axios@0.18.0", Name: "axios", Version: "0.18.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/axios/-/axios-0.18.0.tgz"}}},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bcrypt-pbkdf/-/bcrypt-pbkdf-1.0.2.tgz"}}},
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz"}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz"}}},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/caseless/-/caseless-0.12.0.tgz"}}},
		{ID: "chalk@2.4.2", Name: "chalk", Version: "2.4.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/chalk/-/chalk-2.4.2.tgz"}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/color-convert/-/color-convert-1.9.3.tgz"}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/color-name/-/color-name-1.1.3.tgz"}}},
		{ID: "combined-stream@1.0.7", Name: "combined-stream", Version: "1.0.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/combined-stream/-/combined-stream-1.0.7.tgz"}}},
		{ID: "commander@2.20.0", Name: "commander", Version: "2.20.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/commander/-/commander-2.20.0.tgz"}}},
		{ID: "content-disposition@0.5.2", Name: "content-disposition", Version: "0.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-disposition/-/content-disposition-0.5.2.tgz"}}},
		{ID: "content-type@1.0.4", Name: "content-type", Version: "1.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-type/-/content-type-1.0.4.tgz"}}},
		{ID: "cookie@0.3.1", Name: "cookie", Version: "0.3.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/cookie/-/cookie-0.3.1.tgz"}}},
		{ID: "cookie-signature@1.0.6", Name: "cookie-signature", Version: "1.0.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/cookie-signature/-/cookie-signature-1.0.6.tgz"}}},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/core-util-is/-/core-util-is-1.0.2.tgz"}}},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/dashdash/-/dashdash-1.14.1.tgz"}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}},
		{ID: "debug@3.2.6", Name: "debug", Version: "3.2.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-3.2.6.tgz"}}},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/delayed-stream/-/delayed-stream-1.0.0.tgz"}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}},
		{ID: "destroy@1.0.4", Name: "destroy", Version: "1.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/destroy/-/destroy-1.0.4.tgz"}}},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ecc-jsbn/-/ecc-jsbn-0.1.2.tgz"}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}},
		{ID: "escape-string-regexp@1.0.5", Name: "escape-string-regexp", Version: "1.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-string-regexp/-/escape-string-regexp-1.0.5.tgz"}}},
		{ID: "etag@1.8.1", Name: "etag", Version: "1.8.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/etag/-/etag-1.8.1.tgz"}}},
		{ID: "express@4.16.4", Name: "express", Version: "4.16.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/express/-/express-4.16.4.tgz"}}},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/extend/-/extend-3.0.2.tgz"}}},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/extsprintf/-/extsprintf-1.3.0.tgz"}}},
		{ID: "fast-deep-equal@2.0.1", Name: "fast-deep-equal", Version: "2.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/fast-deep-equal/-/fast-deep-equal-2.0.1.tgz"}}},
		{ID: "fast-json-stable-stringify@2.0.0", Name: "fast-json-stable-stringify", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/fast-json-stable-stringify/-/fast-json-stable-stringify-2.0.0.tgz"}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz"}}},
		{ID: "follow-redirects@1.7.0", Name: "follow-redirects", Version: "1.7.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.7.0.tgz"}}},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/forever-agent/-/forever-agent-0.6.1.tgz"}}},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/form-data/-/form-data-2.3.3.tgz"}}},
		{ID: "forwarded@0.1.2", Name: "forwarded", Version: "0.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/forwarded/-/forwarded-0.1.2.tgz"}}},
		{ID: "fresh@0.5.2", Name: "fresh", Version: "0.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/fresh/-/fresh-0.5.2.tgz"}}},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/getpass/-/getpass-0.1.7.tgz"}}},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/har-schema/-/har-schema-2.0.0.tgz"}}},
		{ID: "har-validator@5.1.3", Name: "har-validator", Version: "5.1.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/har-validator/-/har-validator-5.1.3.tgz"}}},
		{ID: "has-flag@3.0.0", Name: "has-flag", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/has-flag/-/has-flag-3.0.0.tgz"}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz"}}},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-signature/-/http-signature-1.2.0.tgz"}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz"}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz"}}},
		{ID: "ipaddr.js@1.9.0", Name: "ipaddr.js", Version: "1.9.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ipaddr.js/-/ipaddr.js-1.9.0.tgz"}}},
		{ID: "is-buffer@1.1.6", Name: "is-buffer", Version: "1.1.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-buffer/-/is-buffer-1.1.6.tgz"}}},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-typedarray/-/is-typedarray-1.0.0.tgz"}}},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/isstream/-/isstream-0.1.2.tgz"}}},
		{ID: "jquery@3.4.0", Name: "jquery", Version: "3.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jquery/-/jquery-3.4.0.tgz"}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz"}}},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jsbn/-/jsbn-0.1.1.tgz"}}},
		{ID: "json-schema@0.2.3", Name: "json-schema", Version: "0.2.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/json-schema/-/json-schema-0.2.3.tgz"}}},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/json-schema-traverse/-/json-schema-traverse-0.4.1.tgz"}}},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/json-stringify-safe/-/json-stringify-safe-5.0.1.tgz"}}},
		{ID: "jsprim@1.4.1", Name: "jsprim", Version: "1.4.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jsprim/-/jsprim-1.4.1.tgz"}}},
		{ID: "lodash@4.17.11", Name: "lodash", Version: "4.17.11", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz"}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz"}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz"}}},
		{ID: "merge-descriptors@1.0.1", Name: "merge-descriptors", Version: "1.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/merge-descriptors/-/merge-descriptors-1.0.1.tgz"}}},
		{ID: "methods@1.1.2", Name: "methods", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/methods/-/methods-1.1.2.tgz"}}},
		{ID: "mime@1.4.1", Name: "mime", Version: "1.4.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime/-/mime-1.4.1.tgz"}}},
		{ID: "mime-db@1.40.0", Name: "mime-db", Version: "1.40.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-db/-/mime-db-1.40.0.tgz"}}},
		{ID: "mime-types@2.1.24", Name: "mime-types", Version: "2.1.24", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-types/-/mime-types-2.1.24.tgz"}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz"}}},
		{ID: "negotiator@0.6.1", Name: "negotiator", Version: "0.6.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/negotiator/-/negotiator-0.6.1.tgz"}}},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/oauth-sign/-/oauth-sign-0.9.0.tgz"}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/object-assign/-/object-assign-4.1.1.tgz"}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz"}}},
		{ID: "path-to-regexp@0.1.7", Name: "path-to-regexp", Version: "0.1.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-0.1.7.tgz"}}},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/performance-now/-/performance-now-2.1.0.tgz"}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/promise/-/promise-8.0.3.tgz"}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/prop-types/-/prop-types-15.7.2.tgz"}}},
		{ID: "proxy-addr@2.0.5", Name: "proxy-addr", Version: "2.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.5.tgz"}}},
		{ID: "psl@1.1.31", Name: "psl", Version: "1.1.31", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/psl/-/psl-1.1.31.tgz"}}},
		{ID: "punycode@1.4.1", Name: "punycode", Version: "1.4.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/punycode/-/punycode-1.4.1.tgz"}}},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/punycode/-/punycode-2.1.1.tgz"}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"}}},
		{ID: "range-parser@1.2.0", Name: "range-parser", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/range-parser/-/range-parser-1.2.0.tgz"}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz"}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react/-/react-16.8.6.tgz"}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/react-is/-/react-is-16.8.6.tgz"}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/redux/-/redux-4.0.1.tgz"}}},
		{ID: "request@2.88.0", Name: "request", Version: "2.88.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/request/-/request-2.88.0.tgz"}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.1.2.tgz"}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz"}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/scheduler/-/scheduler-0.13.6.tgz"}}},
		{ID: "send@0.16.2", Name: "send", Version: "0.16.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/send/-/send-0.16.2.tgz"}}},
		{ID: "serve-static@1.13.2", Name: "serve-static", Version: "1.13.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/serve-static/-/serve-static-1.13.2.tgz"}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz"}}},
		{ID: "sshpk@1.16.1", Name: "sshpk", Version: "1.16.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/sshpk/-/sshpk-1.16.1.tgz"}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz"}}},
		{ID: "supports-color@5.5.0", Name: "supports-color", Version: "5.5.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/supports-color/-/supports-color-5.5.0.tgz"}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/symbol-observable/-/symbol-observable-1.2.0.tgz"}}},
		{ID: "tough-cookie@2.4.3", Name: "tough-cookie", Version: "2.4.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/tough-cookie/-/tough-cookie-2.4.3.tgz"}}},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/tunnel-agent/-/tunnel-agent-0.6.0.tgz"}}},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/tweetnacl/-/tweetnacl-0.14.5.tgz"}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz"}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz"}}},
		{ID: "uri-js@4.2.2", Name: "uri-js", Version: "4.2.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/uri-js/-/uri-js-4.2.2.tgz"}}},
		{ID: "utils-merge@1.0.1", Name: "utils-merge", Version: "1.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/utils-merge/-/utils-merge-1.0.1.tgz"}}},
		{ID: "uuid@3.3.2", Name: "uuid", Version: "3.3.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/uuid/-/uuid-3.3.2.tgz"}}},
		{ID: "vary@1.1.2", Name: "vary", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/vary/-/vary-1.1.2.tgz"}}},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/verror/-/verror-1.10.0.tgz"}}},
		{ID: "vue@2.6.10", Name: "vue", Version: "2.6.10", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/vue/-/vue-2.6.10.tgz"}}},
	}

	npmManyDeps = []types.Dependency{
		{
			ID:        "accepts@1.3.6",
			DependsOn: []string{"mime-types@2.1.24", "negotiator@0.6.1"},
		},
		{
			ID:        "ajv@6.10.0",
			DependsOn: []string{"fast-deep-equal@2.0.1", "fast-json-stable-stringify@2.0.0", "json-schema-traverse@0.4.1", "uri-js@4.2.2"},
		},
		{
			ID:        "ansi-styles@3.2.1",
			DependsOn: []string{"color-convert@1.9.3"},
		},
		{
			ID:        "asn1@0.2.4",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "async@2.6.2",
			DependsOn: []string{"lodash@4.17.11"},
		},
		{
			ID:        "axios@0.18.0",
			DependsOn: []string{"follow-redirects@1.7.0", "is-buffer@1.1.6"},
		},
		{
			ID:        "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{"tweetnacl@0.14.5"},
		},
		{
			ID:        "body-parser@1.18.3",
			DependsOn: []string{"bytes@3.0.0", "content-type@1.0.4", "debug@2.6.9", "depd@1.1.2", "http-errors@1.6.3", "iconv-lite@0.4.23", "on-finished@2.3.0", "qs@6.5.2", "raw-body@2.3.3", "type-is@1.6.18"},
		},
		{
			ID:        "chalk@2.4.2",
			DependsOn: []string{"ansi-styles@3.2.1", "escape-string-regexp@1.0.5", "supports-color@5.5.0"},
		},
		{
			ID:        "color-convert@1.9.3",
			DependsOn: []string{"color-name@1.1.3"},
		},
		{
			ID:        "combined-stream@1.0.7",
			DependsOn: []string{"delayed-stream@1.0.0"},
		},
		{
			ID:        "dashdash@1.14.1",
			DependsOn: []string{"assert-plus@1.0.0"},
		},
		{
			ID:        "debug@3.2.6",
			DependsOn: []string{"ms@2.1.1"},
		},
		{
			ID:        "ecc-jsbn@0.1.2",
			DependsOn: []string{"jsbn@0.1.1", "safer-buffer@2.1.2"},
		},
		{
			ID:        "express@4.16.4",
			DependsOn: []string{"accepts@1.3.6", "array-flatten@1.1.1", "body-parser@1.18.3", "content-disposition@0.5.2", "content-type@1.0.4", "cookie-signature@1.0.6", "cookie@0.3.1", "debug@2.6.9", "depd@1.1.2", "encodeurl@1.0.2", "escape-html@1.0.3", "etag@1.8.1", "finalhandler@1.1.1", "fresh@0.5.2", "merge-descriptors@1.0.1", "methods@1.1.2", "on-finished@2.3.0", "parseurl@1.3.3", "path-to-regexp@0.1.7", "proxy-addr@2.0.5", "qs@6.5.2", "range-parser@1.2.0", "safe-buffer@5.1.2", "send@0.16.2", "serve-static@1.13.2", "setprototypeof@1.1.0", "statuses@1.4.0", "type-is@1.6.18", "utils-merge@1.0.1", "vary@1.1.2"},
		},
		{
			ID:        "finalhandler@1.1.1",
			DependsOn: []string{"debug@2.6.9", "encodeurl@1.0.2", "escape-html@1.0.3", "on-finished@2.3.0", "parseurl@1.3.3", "statuses@1.4.0", "unpipe@1.0.0"},
		},
		{
			ID:        "follow-redirects@1.7.0",
			DependsOn: []string{"debug@3.2.6"},
		},
		{
			ID:        "form-data@2.3.3",
			DependsOn: []string{"asynckit@0.4.0", "combined-stream@1.0.7", "mime-types@2.1.24"},
		},
		{
			ID:        "getpass@0.1.7",
			DependsOn: []string{"assert-plus@1.0.0"},
		},
		{
			ID:        "har-validator@5.1.3",
			DependsOn: []string{"ajv@6.10.0", "har-schema@2.0.0"},
		},
		{
			ID:        "http-errors@1.6.3",
			DependsOn: []string{"depd@1.1.2", "inherits@2.0.3", "setprototypeof@1.1.0", "statuses@1.4.0"},
		},
		{
			ID:        "http-signature@1.2.0",
			DependsOn: []string{"assert-plus@1.0.0", "jsprim@1.4.1", "sshpk@1.16.1"},
		},
		{
			ID:        "iconv-lite@0.4.23",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "jsprim@1.4.1",
			DependsOn: []string{"assert-plus@1.0.0", "extsprintf@1.3.0", "json-schema@0.2.3", "verror@1.10.0"},
		},
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "mime-types@2.1.24",
			DependsOn: []string{"mime-db@1.40.0"},
		},
		{
			ID:        "on-finished@2.3.0",
			DependsOn: []string{"ee-first@1.1.1"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "proxy-addr@2.0.5",
			DependsOn: []string{"forwarded@0.1.2", "ipaddr.js@1.9.0"},
		},
		{
			ID:        "raw-body@2.3.3",
			DependsOn: []string{"bytes@3.0.0", "http-errors@1.6.3", "iconv-lite@0.4.23", "unpipe@1.0.0"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "request@2.88.0",
			DependsOn: []string{"aws-sign2@0.7.0", "aws4@1.8.0", "caseless@0.12.0", "combined-stream@1.0.7", "extend@3.0.2", "forever-agent@0.6.1", "form-data@2.3.3", "har-validator@5.1.3", "http-signature@1.2.0", "is-typedarray@1.0.0", "isstream@0.1.2", "json-stringify-safe@5.0.1", "mime-types@2.1.24", "oauth-sign@0.9.0", "performance-now@2.1.0", "qs@6.5.2", "safe-buffer@5.1.2", "tough-cookie@2.4.3", "tunnel-agent@0.6.0", "uuid@3.3.2"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
		{
			ID:        "send@0.16.2",
			DependsOn: []string{"debug@2.6.9", "depd@1.1.2", "destroy@1.0.4", "encodeurl@1.0.2", "escape-html@1.0.3", "etag@1.8.1", "fresh@0.5.2", "http-errors@1.6.3", "mime@1.4.1", "ms@2.0.0", "on-finished@2.3.0", "range-parser@1.2.0", "statuses@1.4.0"},
		},
		{
			ID:        "serve-static@1.13.2",
			DependsOn: []string{"encodeurl@1.0.2", "escape-html@1.0.3", "parseurl@1.3.3", "send@0.16.2"},
		},
		{
			ID:        "sshpk@1.16.1",
			DependsOn: []string{"asn1@0.2.4", "assert-plus@1.0.0", "bcrypt-pbkdf@1.0.2", "dashdash@1.14.1", "ecc-jsbn@0.1.2", "getpass@0.1.7", "jsbn@0.1.1", "safer-buffer@2.1.2", "tweetnacl@0.14.5"},
		},
		{
			ID:        "tough-cookie@2.4.3",
			DependsOn: []string{"psl@1.1.31", "punycode@1.4.1"},
		},
		{
			ID:        "tunnel-agent@0.6.0",
			DependsOn: []string{"safe-buffer@5.1.2"},
		},
		{
			ID:        "type-is@1.6.18",
			DependsOn: []string{"media-typer@0.3.0", "mime-types@2.1.24"},
		},
		{
			ID:        "uri-js@4.2.2",
			DependsOn: []string{"punycode@2.1.1"},
		},
		{
			ID:        "verror@1.10.0",
			DependsOn: []string{"assert-plus@1.0.0", "core-util-is@1.0.2", "extsprintf@1.3.0"},
		},
		{
			ID:        "debug@2.6.9",
			DependsOn: []string{"ms@2.0.0"},
		},
		{
			ID:        "supports-color@5.5.0",
			DependsOn: []string{"has-flag@3.0.0"},
		},
	}

	// manually created
	npmNested = []types.Library{
		{ID: "debug@2.0.0", Name: "debug", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.0.0.tgz"}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}},
		{ID: "destroy@1.0.4", Name: "destroy", Version: "1.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/destroy/-/destroy-1.0.4.tgz"}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}},
		{ID: "etag@1.8.1", Name: "etag", Version: "1.8.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/etag/-/etag-1.8.1.tgz"}}},
		{ID: "fresh@0.5.2", Name: "fresh", Version: "0.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/fresh/-/fresh-0.5.2.tgz"}}},
		{ID: "http-errors@1.7.3", Name: "http-errors", Version: "1.7.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.7.3.tgz"}}},
		{ID: "inherits@2.0.4", Name: "inherits", Version: "2.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.4.tgz"}}},
		{ID: "mime@1.6.0", Name: "mime", Version: "1.6.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime/-/mime-1.6.0.tgz"}}},
		{ID: "ms@0.6.2", Name: "ms", Version: "0.6.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-0.6.2.tgz"}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}},
		{ID: "ms@2.1.0", Name: "ms", Version: "2.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.1.0.tgz"}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.1.1.tgz"}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}},
		{ID: "range-parser@1.2.1", Name: "range-parser", Version: "1.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/range-parser/-/range-parser-1.2.1.tgz"}}},
		{ID: "send@0.17.1", Name: "send", Version: "0.17.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/send/-/send-0.17.1.tgz"}}},
		{ID: "setprototypeof@1.1.1", Name: "setprototypeof", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.1.tgz"}}},
		{ID: "statuses@1.5.0", Name: "statuses", Version: "1.5.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.5.0.tgz"}}},
		{ID: "toidentifier@1.0.0", Name: "toidentifier", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/toidentifier/-/toidentifier-1.0.0.tgz"}}}}

	npmNestedDeps = []types.Dependency{{
		ID:        "send@0.17.1",
		DependsOn: []string{"fresh@0.5.2", "ms@2.1.1", "on-finished@2.3.0", "statuses@1.5.0", "escape-html@1.0.3", "depd@1.1.2", "destroy@1.0.4", "encodeurl@1.0.2", "etag@1.8.1", "http-errors@1.7.3", "mime@1.6.0", "range-parser@1.2.1", "debug@2.6.9"},
	}, {
		ID:        "http-errors@1.7.3",
		DependsOn: []string{"depd@1.1.2", "inherits@2.0.4", "setprototypeof@1.1.1", "statuses@1.5.0", "toidentifier@1.0.0"},
	}, {
		ID: "on-finished@2.3.0", DependsOn: []string{"ee-first@1.1.1"},
	}, {
		ID: "debug@2.0.0", DependsOn: []string{"ms@0.6.2"},
	}, {
		ID:        "debug@2.6.9",
		DependsOn: []string{"ms@2.0.0"},
	}}

	npmDeepNested = []types.Library{
		{ID: "ansi-regex@0.2.1", Name: "ansi-regex", Version: "0.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-0.2.1.tgz"}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-2.1.1.tgz"}}},
		{ID: "ansi-regex@6.0.1", Name: "ansi-regex", Version: "6.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-6.0.1.tgz"}}},
		{ID: "camelcase@3.0.0", Name: "camelcase", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/camelcase/-/camelcase-3.0.0.tgz"}}},
		{ID: "cliui@3.2.0", Name: "cliui", Version: "3.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/cliui/-/cliui-3.2.0.tgz"}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/code-point-at/-/code-point-at-1.1.0.tgz"}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/decamelize/-/decamelize-1.2.0.tgz"}}},
		{ID: "eastasianwidth@0.2.0", Name: "eastasianwidth", Version: "0.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/eastasianwidth/-/eastasianwidth-0.2.0.tgz"}}},
		{ID: "emoji-regex@9.2.2", Name: "emoji-regex", Version: "9.2.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/emoji-regex/-/emoji-regex-9.2.2.tgz"}}},
		{ID: "error-ex@1.3.2", Name: "error-ex", Version: "1.3.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/error-ex/-/error-ex-1.3.2.tgz"}}},
		{ID: "find-up@1.1.2", Name: "find-up", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/find-up/-/find-up-1.1.2.tgz"}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/function-bind/-/function-bind-1.1.1.tgz"}}},
		{ID: "get-caller-file@1.0.3", Name: "get-caller-file", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/get-caller-file/-/get-caller-file-1.0.3.tgz"}}},
		{ID: "graceful-fs@4.2.10", Name: "graceful-fs", Version: "4.2.10", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/graceful-fs/-/graceful-fs-4.2.10.tgz"}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/has/-/has-1.0.3.tgz"}}},
		{ID: "hosted-git-info@2.8.9", Name: "hosted-git-info", Version: "2.8.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/hosted-git-info/-/hosted-git-info-2.8.9.tgz"}}},
		{ID: "invert-kv@1.0.0", Name: "invert-kv", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/invert-kv/-/invert-kv-1.0.0.tgz"}}},
		{ID: "is-arrayish@0.2.1", Name: "is-arrayish", Version: "0.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-arrayish/-/is-arrayish-0.2.1.tgz"}}},
		{ID: "is-core-module@2.9.0", Name: "is-core-module", Version: "2.9.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-core-module/-/is-core-module-2.9.0.tgz"}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-1.0.0.tgz"}}},
		{ID: "is-utf8@0.2.1", Name: "is-utf8", Version: "0.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/is-utf8/-/is-utf8-0.2.1.tgz"}}},
		{ID: "lcid@1.0.0", Name: "lcid", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/lcid/-/lcid-1.0.0.tgz"}}},
		{ID: "load-json-file@1.1.0", Name: "load-json-file", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/load-json-file/-/load-json-file-1.1.0.tgz"}}},
		{ID: "normalize-package-data@2.5.0", Name: "normalize-package-data", Version: "2.5.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/normalize-package-data/-/normalize-package-data-2.5.0.tgz"}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/number-is-nan/-/number-is-nan-1.0.1.tgz"}}},
		{ID: "os-locale@1.4.0", Name: "os-locale", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/os-locale/-/os-locale-1.4.0.tgz"}}},
		{ID: "parse-json@2.2.0", Name: "parse-json", Version: "2.2.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parse-json/-/parse-json-2.2.0.tgz"}}},
		{ID: "path-exists@2.1.0", Name: "path-exists", Version: "2.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/path-exists/-/path-exists-2.1.0.tgz"}}},
		{ID: "path-parse@1.0.7", Name: "path-parse", Version: "1.0.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/path-parse/-/path-parse-1.0.7.tgz"}}},
		{ID: "path-type@1.1.0", Name: "path-type", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/path-type/-/path-type-1.1.0.tgz"}}},
		{ID: "pify@2.3.0", Name: "pify", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/pify/-/pify-2.3.0.tgz"}}},
		{ID: "pinkie@2.0.4", Name: "pinkie", Version: "2.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/pinkie/-/pinkie-2.0.4.tgz"}}},
		{ID: "pinkie-promise@2.0.1", Name: "pinkie-promise", Version: "2.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/pinkie-promise/-/pinkie-promise-2.0.1.tgz"}}},
		{ID: "read-pkg@1.1.0", Name: "read-pkg", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/read-pkg/-/read-pkg-1.1.0.tgz"}}},
		{ID: "read-pkg-up@1.0.1", Name: "read-pkg-up", Version: "1.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/read-pkg-up/-/read-pkg-up-1.0.1.tgz"}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/require-directory/-/require-directory-2.1.1.tgz"}}},
		{ID: "require-main-filename@1.0.1", Name: "require-main-filename", Version: "1.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/require-main-filename/-/require-main-filename-1.0.1.tgz"}}},
		{ID: "resolve@1.22.0", Name: "resolve", Version: "1.22.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/resolve/-/resolve-1.22.0.tgz"}}},
		{ID: "semver@5.7.1", Name: "semver", Version: "5.7.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/semver/-/semver-5.7.1.tgz"}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/set-blocking/-/set-blocking-2.0.0.tgz"}}},
		{ID: "spdx-correct@3.1.1", Name: "spdx-correct", Version: "3.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/spdx-correct/-/spdx-correct-3.1.1.tgz"}}},
		{ID: "spdx-exceptions@2.3.0", Name: "spdx-exceptions", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/spdx-exceptions/-/spdx-exceptions-2.3.0.tgz"}}},
		{ID: "spdx-expression-parse@3.0.1", Name: "spdx-expression-parse", Version: "3.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/spdx-expression-parse/-/spdx-expression-parse-3.0.1.tgz"}}},
		{ID: "spdx-license-ids@3.0.11", Name: "spdx-license-ids", Version: "3.0.11", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/spdx-license-ids/-/spdx-license-ids-3.0.11.tgz"}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/string-width/-/string-width-1.0.2.tgz"}}},
		{ID: "string-width@5.1.2", Name: "string-width", Version: "5.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/string-width/-/string-width-5.1.2.tgz"}}},
		{ID: "strip-ansi@1.0.0", Name: "strip-ansi", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-1.0.0.tgz"}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-3.0.1.tgz"}}},
		{ID: "strip-ansi@7.0.1", Name: "strip-ansi", Version: "7.0.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-7.0.1.tgz"}}},
		{ID: "strip-bom@2.0.0", Name: "strip-bom", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/strip-bom/-/strip-bom-2.0.0.tgz"}}},
		{ID: "supports-preserve-symlinks-flag@1.0.0", Name: "supports-preserve-symlinks-flag", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/supports-preserve-symlinks-flag/-/supports-preserve-symlinks-flag-1.0.0.tgz"}}},
		{ID: "validate-npm-package-license@3.0.4", Name: "validate-npm-package-license", Version: "3.0.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/validate-npm-package-license/-/validate-npm-package-license-3.0.4.tgz"}}},
		{ID: "which-module@1.0.0", Name: "which-module", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/which-module/-/which-module-1.0.0.tgz"}}},
		{ID: "wrap-ansi@2.1.0", Name: "wrap-ansi", Version: "2.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/wrap-ansi/-/wrap-ansi-2.1.0.tgz"}}},
		{ID: "y18n@3.2.2", Name: "y18n", Version: "3.2.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/y18n/-/y18n-3.2.2.tgz"}}},
		{ID: "yargs@6.6.0", Name: "yargs", Version: "6.6.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/yargs/-/yargs-6.6.0.tgz"}}},
		{ID: "yargs-parser@4.2.1", Name: "yargs-parser", Version: "4.2.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/yargs-parser/-/yargs-parser-4.2.1.tgz"}}}}

	npmDeepNestedDeps = []types.Dependency{
		{
			ID: "cliui@3.2.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"wrap-ansi@2.1.0",
			},
		},
		{
			ID:        "error-ex@1.3.2",
			DependsOn: []string{"is-arrayish@0.2.1"},
		},
		{
			ID: "find-up@1.1.2",
			DependsOn: []string{"path-exists@2.1.0",
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID:        "has@1.0.3",
			DependsOn: []string{"function-bind@1.1.1"},
		},
		{
			ID:        "is-core-module@2.9.0",
			DependsOn: []string{"has@1.0.3"},
		},
		{
			ID:        "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{"number-is-nan@1.0.1"},
		},
		{
			ID:        "lcid@1.0.0",
			DependsOn: []string{"invert-kv@1.0.0"},
		},
		{
			ID: "load-json-file@1.1.0",
			DependsOn: []string{
				"graceful-fs@4.2.10",
				"parse-json@2.2.0",
				"pify@2.3.0",
				"pinkie-promise@2.0.1",
				"strip-bom@2.0.0",
			},
		},
		{
			ID: "normalize-package-data@2.5.0",
			DependsOn: []string{
				"hosted-git-info@2.8.9",
				"resolve@1.22.0",
				"semver@5.7.1",
				"validate-npm-package-license@3.0.4",
			},
		},
		{
			ID:        "os-locale@1.4.0",
			DependsOn: []string{"lcid@1.0.0"},
		},
		{
			ID:        "parse-json@2.2.0",
			DependsOn: []string{"error-ex@1.3.2"},
		},
		{
			ID:        "path-exists@2.1.0",
			DependsOn: []string{"pinkie-promise@2.0.1"},
		},
		{
			ID: "path-type@1.1.0",
			DependsOn: []string{
				"graceful-fs@4.2.10",
				"pify@2.3.0",
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID:        "pinkie-promise@2.0.1",
			DependsOn: []string{"pinkie@2.0.4"},
		},
		{
			ID: "read-pkg-up@1.0.1",
			DependsOn: []string{
				"find-up@1.1.2",
				"read-pkg@1.1.0",
			},
		},
		{
			ID: "read-pkg@1.1.0",
			DependsOn: []string{
				"load-json-file@1.1.0",
				"normalize-package-data@2.5.0",
				"path-type@1.1.0",
			},
		},
		{
			ID: "resolve@1.22.0",
			DependsOn: []string{
				"is-core-module@2.9.0",
				"path-parse@1.0.7",
				"supports-preserve-symlinks-flag@1.0.0",
			},
		},
		{
			ID: "spdx-correct@3.1.1",
			DependsOn: []string{
				"spdx-expression-parse@3.0.1",
				"spdx-license-ids@3.0.11",
			},
		},
		{
			ID: "spdx-expression-parse@3.0.1",
			DependsOn: []string{
				"spdx-exceptions@2.3.0",
				"spdx-license-ids@3.0.11",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "string-width@5.1.2",
			DependsOn: []string{
				"eastasianwidth@0.2.0",
				"emoji-regex@9.2.2",
				"strip-ansi@7.0.1",
			},
		},
		{
			ID:        "strip-ansi@1.0.0",
			DependsOn: []string{"ansi-regex@0.2.1"},
		},
		{
			ID:        "strip-ansi@3.0.1",
			DependsOn: []string{"ansi-regex@2.1.1"},
		},
		{
			ID:        "strip-ansi@7.0.1",
			DependsOn: []string{"ansi-regex@6.0.1"},
		},
		{
			ID:        "strip-bom@2.0.0",
			DependsOn: []string{"is-utf8@0.2.1"},
		},
		{
			ID: "validate-npm-package-license@3.0.4",
			DependsOn: []string{
				"spdx-correct@3.1.1",
				"spdx-expression-parse@3.0.1",
			},
		},
		{
			ID: "wrap-ansi@2.1.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID:        "yargs-parser@4.2.1",
			DependsOn: []string{"camelcase@3.0.0"},
		},
		{
			ID: "yargs@6.6.0",
			DependsOn: []string{
				"camelcase@3.0.0",
				"cliui@3.2.0",
				"decamelize@1.2.0",
				"get-caller-file@1.0.3",
				"os-locale@1.4.0",
				"read-pkg-up@1.0.1",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@1.0.2",
				"which-module@1.0.0",
				"y18n@3.2.2",
				"yargs-parser@4.2.1",
			},
		},
	}

	npmWithPkgs = []types.Library{
		{ID: "asap@2.0.7", Name: "asap", Version: "2.0.7", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/asap/-/asap-2.0.7.tgz"}}},
		{ID: "jquery@3.4.0", Name: "jquery", Version: "3.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/jquery/-/jquery-3.4.0.tgz"}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/promise/-/promise-8.0.3.tgz"}}},
		{ID: "moment@2.29.1", Name: "moment", Version: "2.29.1", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/moment/-/moment-2.29.1.tgz"}}},
		{ID: "uuid@8.3.2", Name: "uuid", Version: "8.3.2", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/uuid/-/uuid-8.3.2.tgz"}}},
	}

	npmWithPkgsDeps = []types.Dependency{
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.7"},
		},
	}
)
