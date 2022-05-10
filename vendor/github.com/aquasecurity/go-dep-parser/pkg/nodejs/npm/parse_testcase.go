package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmNormal = []types.Library{
		{"asap", "2.0.6", ""},
		{"jquery", "3.4.0", ""},
		{"promise", "8.0.3", ""},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmReact = []types.Library{
		{"asap", "2.0.6", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"loose-envify", "1.4.0", ""},
		{"object-assign", "4.1.1", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"react", "16.8.6", ""},
		{"react-is", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"scheduler", "0.13.6", ""},
		{"symbol-observable", "1.2.0", ""},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmWithDev = []types.Library{
		{"asap", "2.0.6", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"loose-envify", "1.4.0", ""},
		{"object-assign", "4.1.1", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"react", "16.8.6", ""},
		{"react-is", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"scheduler", "0.13.6", ""},
		{"symbol-observable", "1.2.0", ""},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm install --save lodash request chalk commander express async axios vue
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmMany = []types.Library{
		{"accepts", "1.3.6", ""},
		{"ajv", "6.10.0", ""},
		{"ansi-styles", "3.2.1", ""},
		{"array-flatten", "1.1.1", ""},
		{"asap", "2.0.6", ""},
		{"asn1", "0.2.4", ""},
		{"assert-plus", "1.0.0", ""},
		{"async", "2.6.2", ""},
		{"asynckit", "0.4.0", ""},
		{"aws-sign2", "0.7.0", ""},
		{"aws4", "1.8.0", ""},
		{"axios", "0.18.0", ""},
		{"bcrypt-pbkdf", "1.0.2", ""},
		{"body-parser", "1.18.3", ""},
		{"bytes", "3.0.0", ""},
		{"caseless", "0.12.0", ""},
		{"chalk", "2.4.2", ""},
		{"color-convert", "1.9.3", ""},
		{"color-name", "1.1.3", ""},
		{"combined-stream", "1.0.7", ""},
		{"commander", "2.20.0", ""},
		{"content-disposition", "0.5.2", ""},
		{"content-type", "1.0.4", ""},
		{"cookie-signature", "1.0.6", ""},
		{"cookie", "0.3.1", ""},
		{"core-util-is", "1.0.2", ""},
		{"dashdash", "1.14.1", ""},
		{"debug", "2.6.9", ""},
		{"debug", "3.2.6", ""},
		{"delayed-stream", "1.0.0", ""},
		{"depd", "1.1.2", ""},
		{"destroy", "1.0.4", ""},
		{"ecc-jsbn", "0.1.2", ""},
		{"ee-first", "1.1.1", ""},
		{"encodeurl", "1.0.2", ""},
		{"escape-html", "1.0.3", ""},
		{"escape-string-regexp", "1.0.5", ""},
		{"etag", "1.8.1", ""},
		{"express", "4.16.4", ""},
		{"extend", "3.0.2", ""},
		{"extsprintf", "1.3.0", ""},
		{"fast-deep-equal", "2.0.1", ""},
		{"fast-json-stable-stringify", "2.0.0", ""},
		{"finalhandler", "1.1.1", ""},
		{"follow-redirects", "1.7.0", ""},
		{"forever-agent", "0.6.1", ""},
		{"form-data", "2.3.3", ""},
		{"forwarded", "0.1.2", ""},
		{"fresh", "0.5.2", ""},
		{"getpass", "0.1.7", ""},
		{"har-schema", "2.0.0", ""},
		{"har-validator", "5.1.3", ""},
		{"has-flag", "3.0.0", ""},
		{"http-errors", "1.6.3", ""},
		{"http-signature", "1.2.0", ""},
		{"iconv-lite", "0.4.23", ""},
		{"inherits", "2.0.3", ""},
		{"ipaddr.js", "1.9.0", ""},
		{"is-buffer", "1.1.6", ""},
		{"is-typedarray", "1.0.0", ""},
		{"isstream", "0.1.2", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"jsbn", "0.1.1", ""},
		{"json-schema-traverse", "0.4.1", ""},
		{"json-schema", "0.2.3", ""},
		{"json-stringify-safe", "5.0.1", ""},
		{"jsprim", "1.4.1", ""},
		{"lodash", "4.17.11", ""},
		{"loose-envify", "1.4.0", ""},
		{"media-typer", "0.3.0", ""},
		{"merge-descriptors", "1.0.1", ""},
		{"methods", "1.1.2", ""},
		{"mime-db", "1.40.0", ""},
		{"mime-types", "2.1.24", ""},
		{"mime", "1.4.1", ""},
		{"ms", "2.0.0", ""},
		{"ms", "2.1.1", ""},
		{"negotiator", "0.6.1", ""},
		{"oauth-sign", "0.9.0", ""},
		{"object-assign", "4.1.1", ""},
		{"on-finished", "2.3.0", ""},
		{"parseurl", "1.3.3", ""},
		{"path-to-regexp", "0.1.7", ""},
		{"performance-now", "2.1.0", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"proxy-addr", "2.0.5", ""},
		{"psl", "1.1.31", ""},
		{"punycode", "1.4.1", ""},
		{"punycode", "2.1.1", ""},
		{"qs", "6.5.2", ""},
		{"range-parser", "1.2.0", ""},
		{"raw-body", "2.3.3", ""},
		{"react-is", "16.8.6", ""},
		{"react", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"request", "2.88.0", ""},
		{"safe-buffer", "5.1.2", ""},
		{"safer-buffer", "2.1.2", ""},
		{"scheduler", "0.13.6", ""},
		{"send", "0.16.2", ""},
		{"serve-static", "1.13.2", ""},
		{"setprototypeof", "1.1.0", ""},
		{"sshpk", "1.16.1", ""},
		{"statuses", "1.4.0", ""},
		{"supports-color", "5.5.0", ""},
		{"symbol-observable", "1.2.0", ""},
		{"tough-cookie", "2.4.3", ""},
		{"tunnel-agent", "0.6.0", ""},
		{"tweetnacl", "0.14.5", ""},
		{"type-is", "1.6.18", ""},
		{"unpipe", "1.0.0", ""},
		{"uri-js", "4.2.2", ""},
		{"utils-merge", "1.0.1", ""},
		{"uuid", "3.3.2", ""},
		{"vary", "1.1.2", ""},
		{"verror", "1.10.0", ""},
		{"vue", "2.6.10", ""},
	}

	// manually created
	npmNested = []types.Library{
		{"debug", "2.0.0", ""},
		{"debug", "2.6.9", ""},
		{"ms", "0.6.2", ""},
		{"ms", "2.0.0", ""},
		{"ms", "2.1.0", ""},
		{"ms", "2.1.1", ""},
		{"send", "0.17.1", ""},
	}
)
