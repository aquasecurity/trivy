package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmNormal = []types.Library{
		{Name: "asap", Version: "2.0.6"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "promise", Version: "8.0.3"},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmReact = []types.Library{
		{Name: "asap", Version: "2.0.6"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "react", Version: "16.8.6"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "symbol-observable", Version: "1.2.0"},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmWithDev = []types.Library{
		{Name: "asap", Version: "2.0.6"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "react", Version: "16.8.6"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "symbol-observable", Version: "1.2.0"},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm install --save lodash request chalk commander express async axios vue
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmMany = []types.Library{
		{Name: "accepts", Version: "1.3.6"},
		{Name: "ajv", Version: "6.10.0"},
		{Name: "ansi-styles", Version: "3.2.1"},
		{Name: "array-flatten", Version: "1.1.1"},
		{Name: "asap", Version: "2.0.6"},
		{Name: "asn1", Version: "0.2.4"},
		{Name: "assert-plus", Version: "1.0.0"},
		{Name: "async", Version: "2.6.2"},
		{Name: "asynckit", Version: "0.4.0"},
		{Name: "aws-sign2", Version: "0.7.0"},
		{Name: "aws4", Version: "1.8.0"},
		{Name: "axios", Version: "0.18.0"},
		{Name: "bcrypt-pbkdf", Version: "1.0.2"},
		{Name: "body-parser", Version: "1.18.3"},
		{Name: "bytes", Version: "3.0.0"},
		{Name: "caseless", Version: "0.12.0"},
		{Name: "chalk", Version: "2.4.2"},
		{Name: "color-convert", Version: "1.9.3"},
		{Name: "color-name", Version: "1.1.3"},
		{Name: "combined-stream", Version: "1.0.7"},
		{Name: "commander", Version: "2.20.0"},
		{Name: "content-disposition", Version: "0.5.2"},
		{Name: "content-type", Version: "1.0.4"},
		{Name: "cookie-signature", Version: "1.0.6"},
		{Name: "cookie", Version: "0.3.1"},
		{Name: "core-util-is", Version: "1.0.2"},
		{Name: "dashdash", Version: "1.14.1"},
		{Name: "debug", Version: "2.6.9"},
		{Name: "debug", Version: "3.2.6"},
		{Name: "delayed-stream", Version: "1.0.0"},
		{Name: "depd", Version: "1.1.2"},
		{Name: "destroy", Version: "1.0.4"},
		{Name: "ecc-jsbn", Version: "0.1.2"},
		{Name: "ee-first", Version: "1.1.1"},
		{Name: "encodeurl", Version: "1.0.2"},
		{Name: "escape-html", Version: "1.0.3"},
		{Name: "escape-string-regexp", Version: "1.0.5"},
		{Name: "etag", Version: "1.8.1"},
		{Name: "express", Version: "4.16.4"},
		{Name: "extend", Version: "3.0.2"},
		{Name: "extsprintf", Version: "1.3.0"},
		{Name: "fast-deep-equal", Version: "2.0.1"},
		{Name: "fast-json-stable-stringify", Version: "2.0.0"},
		{Name: "finalhandler", Version: "1.1.1"},
		{Name: "follow-redirects", Version: "1.7.0"},
		{Name: "forever-agent", Version: "0.6.1"},
		{Name: "form-data", Version: "2.3.3"},
		{Name: "forwarded", Version: "0.1.2"},
		{Name: "fresh", Version: "0.5.2"},
		{Name: "getpass", Version: "0.1.7"},
		{Name: "har-schema", Version: "2.0.0"},
		{Name: "har-validator", Version: "5.1.3"},
		{Name: "has-flag", Version: "3.0.0"},
		{Name: "http-errors", Version: "1.6.3"},
		{Name: "http-signature", Version: "1.2.0"},
		{Name: "iconv-lite", Version: "0.4.23"},
		{Name: "inherits", Version: "2.0.3"},
		{Name: "ipaddr.js", Version: "1.9.0"},
		{Name: "is-buffer", Version: "1.1.6"},
		{Name: "is-typedarray", Version: "1.0.0"},
		{Name: "isstream", Version: "0.1.2"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "jsbn", Version: "0.1.1"},
		{Name: "json-schema-traverse", Version: "0.4.1"},
		{Name: "json-schema", Version: "0.2.3"},
		{Name: "json-stringify-safe", Version: "5.0.1"},
		{Name: "jsprim", Version: "1.4.1"},
		{Name: "lodash", Version: "4.17.11"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "media-typer", Version: "0.3.0"},
		{Name: "merge-descriptors", Version: "1.0.1"},
		{Name: "methods", Version: "1.1.2"},
		{Name: "mime-db", Version: "1.40.0"},
		{Name: "mime-types", Version: "2.1.24"},
		{Name: "mime", Version: "1.4.1"},
		{Name: "ms", Version: "2.0.0"},
		{Name: "ms", Version: "2.1.1"},
		{Name: "negotiator", Version: "0.6.1"},
		{Name: "oauth-sign", Version: "0.9.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "on-finished", Version: "2.3.0"},
		{Name: "parseurl", Version: "1.3.3"},
		{Name: "path-to-regexp", Version: "0.1.7"},
		{Name: "performance-now", Version: "2.1.0"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "proxy-addr", Version: "2.0.5"},
		{Name: "psl", Version: "1.1.31"},
		{Name: "punycode", Version: "1.4.1"},
		{Name: "punycode", Version: "2.1.1"},
		{Name: "qs", Version: "6.5.2"},
		{Name: "range-parser", Version: "1.2.0"},
		{Name: "raw-body", Version: "2.3.3"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "react", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "request", Version: "2.88.0"},
		{Name: "safe-buffer", Version: "5.1.2"},
		{Name: "safer-buffer", Version: "2.1.2"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "send", Version: "0.16.2"},
		{Name: "serve-static", Version: "1.13.2"},
		{Name: "setprototypeof", Version: "1.1.0"},
		{Name: "sshpk", Version: "1.16.1"},
		{Name: "statuses", Version: "1.4.0"},
		{Name: "supports-color", Version: "5.5.0"},
		{Name: "symbol-observable", Version: "1.2.0"},
		{Name: "tough-cookie", Version: "2.4.3"},
		{Name: "tunnel-agent", Version: "0.6.0"},
		{Name: "tweetnacl", Version: "0.14.5"},
		{Name: "type-is", Version: "1.6.18"},
		{Name: "unpipe", Version: "1.0.0"},
		{Name: "uri-js", Version: "4.2.2"},
		{Name: "utils-merge", Version: "1.0.1"},
		{Name: "uuid", Version: "3.3.2"},
		{Name: "vary", Version: "1.1.2"},
		{Name: "verror", Version: "1.10.0"},
		{Name: "vue", Version: "2.6.10"},
	}

	// manually created
	npmNested = []types.Library{
		{Name: "debug", Version: "2.0.0"},
		{Name: "debug", Version: "2.6.9"},
		{Name: "ms", Version: "0.6.2"},
		{Name: "ms", Version: "2.0.0"},
		{Name: "ms", Version: "2.1.0"},
		{Name: "ms", Version: "2.1.1"},
		{Name: "send", Version: "0.17.1"},
	}
)
