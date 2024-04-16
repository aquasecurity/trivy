package pnpm

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	// docker run --name node --rm -it node:16-alpine sh
	// npm install -g pnpm
	// pnpm add promise jquery
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: true},\n")}' | sort -u
	pnpmNormal = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Indirect: true},
		{ID: "jquery@3.6.0", Name: "jquery", Version: "3.6.0", Indirect: false},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Indirect: false},
	}
	pnpmNormalDeps = []types.Dependency{
		{
			ID:        "promise@8.1.0",
			DependsOn: []string{"asap@2.0.6"},
		},
	}

	// docker run --name node --rm -it node:16-alpine sh
	// npm install -g pnpm
	// pnpm add react redux
	// pnpm add -D mocha
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: true},\n")}' | sort -u
	pnpmWithDev = []types.Library{
		{ID: "@babel/runtime@7.18.3", Name: "@babel/runtime", Version: "7.18.3", Indirect: true},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true},
		{ID: "react@18.1.0", Name: "react", Version: "18.1.0", Indirect: false},
		{ID: "redux@4.2.0", Name: "redux", Version: "4.2.0", Indirect: false},
		{ID: "regenerator-runtime@0.13.9", Name: "regenerator-runtime", Version: "0.13.9", Indirect: true},
	}
	pnpmWithDevDeps = []types.Dependency{
		{
			ID:        "@babel/runtime@7.18.3",
			DependsOn: []string{"regenerator-runtime@0.13.9"},
		},
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "react@18.1.0",
			DependsOn: []string{"loose-envify@1.4.0"},
		},
		{
			ID:        "redux@4.2.0",
			DependsOn: []string{"@babel/runtime@7.18.3"},
		},
	}

	// docker run --name node --rm -it node:16-alpine sh
	// npm install -g pnpm
	// pnpm add react redux lodash request chalk commander
	// pnpm add -D mocha
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: true},\n")}' | sort -u
	pnpmMany = []types.Library{
		{ID: "@babel/runtime@7.18.3", Name: "@babel/runtime", Version: "7.18.3", Indirect: true},
		{ID: "ajv@6.12.6", Name: "ajv", Version: "6.12.6", Indirect: true},
		{ID: "asn1@0.2.6", Name: "asn1", Version: "0.2.6", Indirect: true},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Indirect: true},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Indirect: true},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Indirect: true},
		{ID: "aws4@1.11.0", Name: "aws4", Version: "1.11.0", Indirect: true},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Indirect: true},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Indirect: true},
		{ID: "chalk@5.0.1", Name: "chalk", Version: "5.0.1", Indirect: false},
		{ID: "combined-stream@1.0.8", Name: "combined-stream", Version: "1.0.8", Indirect: true},
		{ID: "commander@9.3.0", Name: "commander", Version: "9.3.0", Indirect: false},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Indirect: true},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Indirect: true},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Indirect: true},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Indirect: true},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Indirect: true},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Indirect: true},
		{ID: "fast-deep-equal@3.1.3", Name: "fast-deep-equal", Version: "3.1.3", Indirect: true},
		{ID: "fast-json-stable-stringify@2.1.0", Name: "fast-json-stable-stringify", Version: "2.1.0", Indirect: true},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Indirect: true},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Indirect: true},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Indirect: true},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Indirect: true},
		{ID: "har-validator@5.1.5", Name: "har-validator", Version: "5.1.5", Indirect: true},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Indirect: true},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Indirect: true},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Indirect: true},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Indirect: true},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Indirect: true},
		{ID: "json-schema@0.4.0", Name: "json-schema", Version: "0.4.0", Indirect: true},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Indirect: true},
		{ID: "jsprim@1.4.2", Name: "jsprim", Version: "1.4.2", Indirect: true},
		{ID: "lodash@4.17.21", Name: "lodash", Version: "4.17.21", Indirect: false},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true},
		{ID: "mime-db@1.52.0", Name: "mime-db", Version: "1.52.0", Indirect: true},
		{ID: "mime-types@2.1.35", Name: "mime-types", Version: "2.1.35", Indirect: true},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Indirect: true},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Indirect: true},
		{ID: "psl@1.8.0", Name: "psl", Version: "1.8.0", Indirect: true},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Indirect: true},
		{ID: "qs@6.5.3", Name: "qs", Version: "6.5.3", Indirect: true},
		{ID: "react@18.1.0", Name: "react", Version: "18.1.0", Indirect: false},
		{ID: "redux@4.2.0", Name: "redux", Version: "4.2.0", Indirect: false},
		{ID: "regenerator-runtime@0.13.9", Name: "regenerator-runtime", Version: "0.13.9", Indirect: true},
		{ID: "request@2.88.2", Name: "request", Version: "2.88.2", Indirect: false},
		{ID: "safe-buffer@5.2.1", Name: "safe-buffer", Version: "5.2.1", Indirect: true},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true},
		{ID: "sshpk@1.17.0", Name: "sshpk", Version: "1.17.0", Indirect: true},
		{ID: "tough-cookie@2.5.0", Name: "tough-cookie", Version: "2.5.0", Indirect: true},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Indirect: true},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Indirect: true},
		{ID: "uri-js@4.4.1", Name: "uri-js", Version: "4.4.1", Indirect: true},
		{ID: "uuid@3.4.0", Name: "uuid", Version: "3.4.0", Indirect: true},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Indirect: true},
	}
	pnpmManyDeps = []types.Dependency{
		{ID: "@babel/runtime@7.18.3", DependsOn: []string{"regenerator-runtime@0.13.9"}},
		{ID: "ajv@6.12.6", DependsOn: []string{"fast-deep-equal@3.1.3", "fast-json-stable-stringify@2.1.0", "json-schema-traverse@0.4.1", "uri-js@4.4.1"}},
		{ID: "asn1@0.2.6", DependsOn: []string{"safer-buffer@2.1.2"}},
		{ID: "bcrypt-pbkdf@1.0.2", DependsOn: []string{"tweetnacl@0.14.5"}},
		{ID: "combined-stream@1.0.8", DependsOn: []string{"delayed-stream@1.0.0"}},
		{ID: "dashdash@1.14.1", DependsOn: []string{"assert-plus@1.0.0"}},
		{ID: "ecc-jsbn@0.1.2", DependsOn: []string{"jsbn@0.1.1", "safer-buffer@2.1.2"}},
		{ID: "form-data@2.3.3", DependsOn: []string{"asynckit@0.4.0", "combined-stream@1.0.8", "mime-types@2.1.35"}},
		{ID: "getpass@0.1.7", DependsOn: []string{"assert-plus@1.0.0"}},
		{ID: "har-validator@5.1.5", DependsOn: []string{"ajv@6.12.6", "har-schema@2.0.0"}},
		{ID: "http-signature@1.2.0", DependsOn: []string{"assert-plus@1.0.0", "jsprim@1.4.2", "sshpk@1.17.0"}},
		{ID: "jsprim@1.4.2", DependsOn: []string{"assert-plus@1.0.0", "extsprintf@1.3.0", "json-schema@0.4.0", "verror@1.10.0"}},
		{ID: "loose-envify@1.4.0", DependsOn: []string{"js-tokens@4.0.0"}},
		{ID: "mime-types@2.1.35", DependsOn: []string{"mime-db@1.52.0"}},
		{ID: "react@18.1.0", DependsOn: []string{"loose-envify@1.4.0"}},
		{ID: "redux@4.2.0", DependsOn: []string{"@babel/runtime@7.18.3"}},
		{ID: "request@2.88.2", DependsOn: []string{"aws-sign2@0.7.0", "aws4@1.11.0", "caseless@0.12.0", "combined-stream@1.0.8", "extend@3.0.2", "forever-agent@0.6.1", "form-data@2.3.3", "har-validator@5.1.5", "http-signature@1.2.0", "is-typedarray@1.0.0", "isstream@0.1.2", "json-stringify-safe@5.0.1", "mime-types@2.1.35", "oauth-sign@0.9.0", "performance-now@2.1.0", "qs@6.5.3", "safe-buffer@5.2.1", "tough-cookie@2.5.0", "tunnel-agent@0.6.0", "uuid@3.4.0"}},
		{ID: "sshpk@1.17.0", DependsOn: []string{"asn1@0.2.6", "assert-plus@1.0.0", "bcrypt-pbkdf@1.0.2", "dashdash@1.14.1", "ecc-jsbn@0.1.2", "getpass@0.1.7", "jsbn@0.1.1", "safer-buffer@2.1.2", "tweetnacl@0.14.5"}},
		{ID: "tough-cookie@2.5.0", DependsOn: []string{"psl@1.8.0", "punycode@2.1.1"}},
		{ID: "tunnel-agent@0.6.0", DependsOn: []string{"safe-buffer@5.2.1"}},
		{ID: "uri-js@4.4.1", DependsOn: []string{"punycode@2.1.1"}},
		{ID: "verror@1.10.0", DependsOn: []string{"assert-plus@1.0.0", "core-util-is@1.0.2", "extsprintf@1.3.0"}},
	}

	// docker run --name node --rm -it node@sha256:710a2c192ca426e03e4f3ec1869e5c29db855eb6969b74e6c50fd270ffccd3f1 sh
	// npm install -g pnpm@8.5.1
	// mkdir /temp && cd /temp
	// npm install lodash@4.17.21
	// cd ./node_modules/lodash/
	// npm pack
	// mkdir -p /app/foo/bar && cd /app
	// cp /temp/node_modules/lodash/lodash-4.17.21.tgz /app/foo/bar/lodash.tgz
	// npm init -y
	// npm install ./foo/bar/lodash.tgz
	// mkdir package1 && cd package1
	// npm init -y
	// npm install asynckit@0.4.0
	// cd ..
	// npm install ./package1
	// pnpm update
	// pnpm add https://github.com/debug-js/debug/tarball/4.3.4
	// pnpm add https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: false},\n")}' | sort -u
	// manually update `Indirect` fields
	pnpmArchives = []types.Library{
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Indirect: true},
		{ID: "debug@4.3.4", Name: "debug", Version: "4.3.4", Indirect: false},
		{ID: "is-negative@2.0.1", Name: "is-negative", Version: "2.0.1", Indirect: false},
		{ID: "lodash@4.17.21", Name: "lodash", Version: "4.17.21", Indirect: false},
		{ID: "ms@2.1.2", Name: "ms", Version: "2.1.2", Indirect: true},
		{ID: "package1@1.0.0", Name: "package1", Version: "1.0.0", Indirect: false},
	}

	pnpmArchivesDeps = []types.Dependency{
		{
			ID:        "debug@4.3.4",
			DependsOn: []string{"ms@2.1.2"},
		},
		{
			ID:        "package1@1.0.0",
			DependsOn: []string{"asynckit@0.4.0"},
		},
	}

	// docker run --name node --rm -it node@sha256:710a2c192ca426e03e4f3ec1869e5c29db855eb6969b74e6c50fd270ffccd3f1 sh
	// npm install -g pnpm@8.5.1
	// pnpm add promise@8.1.0 jquery@3.6.0
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: true},\n")}' | sort -u
	pnpmV6     = pnpmNormal
	pnpmV6Deps = pnpmNormalDeps

	// docker run --name node --rm -it node@sha256:710a2c192ca426e03e4f3ec1869e5c29db855eb6969b74e6c50fd270ffccd3f1 sh
	// npm install -g pnpm@8.5.1
	// pnpm add react@18.1.0 redux@4.2.0
	// pnpm add -D mocha@10.0.0
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\", Indirect: true},\n")}' | sort -u
	pnpmV6WithDev = []types.Library{
		{ID: "@babel/runtime@7.22.3", Name: "@babel/runtime", Version: "7.22.3", Indirect: true},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true},
		{ID: "react@18.1.0", Name: "react", Version: "18.1.0", Indirect: false},
		{ID: "redux@4.2.0", Name: "redux", Version: "4.2.0", Indirect: false},
		{ID: "regenerator-runtime@0.13.11", Name: "regenerator-runtime", Version: "0.13.11", Indirect: true},
	}
	pnpmV6WithDevDeps = []types.Dependency{
		{
			ID:        "@babel/runtime@7.22.3",
			DependsOn: []string{"regenerator-runtime@0.13.11"},
		},
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "react@18.1.0",
			DependsOn: []string{"loose-envify@1.4.0"},
		},
		{
			ID:        "redux@4.2.0",
			DependsOn: []string{"@babel/runtime@7.22.3"},
		},
	}
)
