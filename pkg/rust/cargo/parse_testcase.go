package cargo

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init normal && cd normal
	// cargo add libc
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoNormal = []types.Library{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0"},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54"},
	}

	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init many && cd many
	// cargo add rand bitflags lazy_static log serde syn regex quote handlebars rocket
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoMany = []types.Library{
		{ID: "many@0.1.0", Name: "many", Version: "0.1.0"},
		{ID: "aho-corasick@0.7.3", Name: "aho-corasick", Version: "0.7.3"},
		{ID: "autocfg@0.1.2", Name: "autocfg", Version: "0.1.2"},
		{ID: "base64@0.10.1", Name: "base64", Version: "0.10.1"},
		{ID: "base64@0.9.3", Name: "base64", Version: "0.9.3"},
		{ID: "bitflags@1.0.4", Name: "bitflags", Version: "1.0.4"},
		{ID: "block-buffer@0.7.3", Name: "block-buffer", Version: "0.7.3"},
		{ID: "block-padding@0.1.4", Name: "block-padding", Version: "0.1.4"},
		{ID: "byte-tools@0.3.1", Name: "byte-tools", Version: "0.3.1"},
		{ID: "byteorder@1.3.1", Name: "byteorder", Version: "1.3.1"},
		{ID: "cc@1.0.36", Name: "cc", Version: "1.0.36"},
		{ID: "cfg-if@0.1.7", Name: "cfg-if", Version: "0.1.7"},
		{ID: "cloudabi@0.0.3", Name: "cloudabi", Version: "0.0.3"},
		{ID: "cookie@0.11.1", Name: "cookie", Version: "0.11.1"},
		{ID: "devise@0.2.0", Name: "devise", Version: "0.2.0"},
		{ID: "devise_codegen@0.2.0", Name: "devise_codegen", Version: "0.2.0"},
		{ID: "devise_core@0.2.0", Name: "devise_core", Version: "0.2.0"},
		{ID: "digest@0.8.0", Name: "digest", Version: "0.8.0"},
		{ID: "fake-simd@0.1.2", Name: "fake-simd", Version: "0.1.2"},
		{ID: "fuchsia-cprng@0.1.1", Name: "fuchsia-cprng", Version: "0.1.1"},
		{ID: "generic-array@0.12.0", Name: "generic-array", Version: "0.12.0"},
		{ID: "handlebars@1.1.0", Name: "handlebars", Version: "1.1.0"},
		{ID: "httparse@1.3.3", Name: "httparse", Version: "1.3.3"},
		{ID: "hyper@0.10.16", Name: "hyper", Version: "0.10.16"},
		{ID: "idna@0.1.5", Name: "idna", Version: "0.1.5"},
		{ID: "indexmap@1.0.2", Name: "indexmap", Version: "1.0.2"},
		{ID: "isatty@0.1.9", Name: "isatty", Version: "0.1.9"},
		{ID: "itoa@0.4.4", Name: "itoa", Version: "0.4.4"},
		{ID: "language-tags@0.2.2", Name: "language-tags", Version: "0.2.2"},
		{ID: "lazy_static@1.3.0", Name: "lazy_static", Version: "1.3.0"},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54"},
		{ID: "log@0.3.9", Name: "log", Version: "0.3.9"},
		{ID: "log@0.4.6", Name: "log", Version: "0.4.6"},
		{ID: "maplit@1.0.1", Name: "maplit", Version: "1.0.1"},
		{ID: "matches@0.1.8", Name: "matches", Version: "0.1.8"},
		{ID: "memchr@2.2.0", Name: "memchr", Version: "2.2.0"},
		{ID: "mime@0.2.6", Name: "mime", Version: "0.2.6"},
		{ID: "num_cpus@1.10.0", Name: "num_cpus", Version: "1.10.0"},
		{ID: "opaque-debug@0.2.2", Name: "opaque-debug", Version: "0.2.2"},
		{ID: "pear@0.1.2", Name: "pear", Version: "0.1.2"},
		{ID: "pear_codegen@0.1.2", Name: "pear_codegen", Version: "0.1.2"},
		{ID: "percent-encoding@1.0.1", Name: "percent-encoding", Version: "1.0.1"},
		{ID: "pest@2.1.1", Name: "pest", Version: "2.1.1"},
		{ID: "pest_derive@2.1.0", Name: "pest_derive", Version: "2.1.0"},
		{ID: "pest_generator@2.1.0", Name: "pest_generator", Version: "2.1.0"},
		{ID: "pest_meta@2.1.1", Name: "pest_meta", Version: "2.1.1"},
		{ID: "proc-macro2@0.4.30", Name: "proc-macro2", Version: "0.4.30"},
		{ID: "quick-error@1.2.2", Name: "quick-error", Version: "1.2.2"},
		{ID: "quote@0.6.12", Name: "quote", Version: "0.6.12"},
		{ID: "rand@0.6.5", Name: "rand", Version: "0.6.5"},
		{ID: "rand_chacha@0.1.1", Name: "rand_chacha", Version: "0.1.1"},
		{ID: "rand_core@0.3.1", Name: "rand_core", Version: "0.3.1"},
		{ID: "rand_core@0.4.0", Name: "rand_core", Version: "0.4.0"},
		{ID: "rand_hc@0.1.0", Name: "rand_hc", Version: "0.1.0"},
		{ID: "rand_isaac@0.1.1", Name: "rand_isaac", Version: "0.1.1"},
		{ID: "rand_jitter@0.1.4", Name: "rand_jitter", Version: "0.1.4"},
		{ID: "rand_os@0.1.3", Name: "rand_os", Version: "0.1.3"},
		{ID: "rand_pcg@0.1.2", Name: "rand_pcg", Version: "0.1.2"},
		{ID: "rand_xorshift@0.1.1", Name: "rand_xorshift", Version: "0.1.1"},
		{ID: "rdrand@0.4.0", Name: "rdrand", Version: "0.4.0"},
		{ID: "redox_syscall@0.1.54", Name: "redox_syscall", Version: "0.1.54"},
		{ID: "regex@1.1.6", Name: "regex", Version: "1.1.6"},
		{ID: "regex-syntax@0.6.6", Name: "regex-syntax", Version: "0.6.6"},
		{ID: "ring@0.13.5", Name: "ring", Version: "0.13.5"},
		{ID: "rocket@0.4.0", Name: "rocket", Version: "0.4.0"},
		{ID: "rocket_codegen@0.4.0", Name: "rocket_codegen", Version: "0.4.0"},
		{ID: "rocket_http@0.4.0", Name: "rocket_http", Version: "0.4.0"},
		{ID: "ryu@0.2.8", Name: "ryu", Version: "0.2.8"},
		{ID: "safemem@0.3.0", Name: "safemem", Version: "0.3.0"},
		{ID: "same-file@1.0.4", Name: "same-file", Version: "1.0.4"},
		{ID: "serde@1.0.91", Name: "serde", Version: "1.0.91"},
		{ID: "serde_json@1.0.39", Name: "serde_json", Version: "1.0.39"},
		{ID: "sha-1@0.8.1", Name: "sha-1", Version: "0.8.1"},
		{ID: "smallvec@0.6.9", Name: "smallvec", Version: "0.6.9"},
		{ID: "state@0.4.1", Name: "state", Version: "0.4.1"},
		{ID: "syn@0.15.34", Name: "syn", Version: "0.15.34"},
		{ID: "thread_local@0.3.6", Name: "thread_local", Version: "0.3.6"},
		{ID: "time@0.1.42", Name: "time", Version: "0.1.42"},
		{ID: "toml@0.4.10", Name: "toml", Version: "0.4.10"},
		{ID: "traitobject@0.1.0", Name: "traitobject", Version: "0.1.0"},
		{ID: "typeable@0.1.2", Name: "typeable", Version: "0.1.2"},
		{ID: "typenum@1.10.0", Name: "typenum", Version: "1.10.0"},
		{ID: "ucd-trie@0.1.1", Name: "ucd-trie", Version: "0.1.1"},
		{ID: "ucd-util@0.1.3", Name: "ucd-util", Version: "0.1.3"},
		{ID: "unicase@1.4.2", Name: "unicase", Version: "1.4.2"},
		{ID: "unicode-bidi@0.3.4", Name: "unicode-bidi", Version: "0.3.4"},
		{ID: "unicode-normalization@0.1.8", Name: "unicode-normalization", Version: "0.1.8"},
		{ID: "unicode-xid@0.1.0", Name: "unicode-xid", Version: "0.1.0"},
		{ID: "untrusted@0.6.2", Name: "untrusted", Version: "0.6.2"},
		{ID: "url@1.7.2", Name: "url", Version: "1.7.2"},
		{ID: "utf8-ranges@1.0.2", Name: "utf8-ranges", Version: "1.0.2"},
		{ID: "version_check@0.1.5", Name: "version_check", Version: "0.1.5"},
		{ID: "walkdir@2.2.7", Name: "walkdir", Version: "2.2.7"},
		{ID: "winapi@0.3.7", Name: "winapi", Version: "0.3.7"},
		{ID: "winapi-i686-pc-windows-gnu@0.4.0", Name: "winapi-i686-pc-windows-gnu", Version: "0.4.0"},
		{ID: "winapi-util@0.1.2", Name: "winapi-util", Version: "0.1.2"},
		{ID: "winapi-x86_64-pc-windows-gnu@0.4.0", Name: "winapi-x86_64-pc-windows-gnu", Version: "0.4.0"},
		{ID: "yansi@0.4.0", Name: "yansi", Version: "0.4.0"},
		{ID: "yansi@0.5.0", Name: "yansi", Version: "0.5.0"},
	}

	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init web && cd web
	// cargo add nickel
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoNickel = []types.Library{
		{ID: "web@0.1.0", Name: "web", Version: "0.1.0"},
		{ID: "aho-corasick@0.7.3", Name: "aho-corasick", Version: "0.7.3"},
		{ID: "base64@0.9.3", Name: "base64", Version: "0.9.3"},
		{ID: "byteorder@1.3.1", Name: "byteorder", Version: "1.3.1"},
		{ID: "cfg-if@0.1.7", Name: "cfg-if", Version: "0.1.7"},
		{ID: "groupable@0.2.0", Name: "groupable", Version: "0.2.0"},
		{ID: "httparse@1.3.3", Name: "httparse", Version: "1.3.3"},
		{ID: "hyper@0.10.16", Name: "hyper", Version: "0.10.16"},
		{ID: "idna@0.1.5", Name: "idna", Version: "0.1.5"},
		{ID: "itoa@0.4.4", Name: "itoa", Version: "0.4.4"},
		{ID: "language-tags@0.2.2", Name: "language-tags", Version: "0.2.2"},
		{ID: "lazy_static@1.3.0", Name: "lazy_static", Version: "1.3.0"},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54"},
		{ID: "log@0.3.9", Name: "log", Version: "0.3.9"},
		{ID: "log@0.4.6", Name: "log", Version: "0.4.6"},
		{ID: "matches@0.1.8", Name: "matches", Version: "0.1.8"},
		{ID: "memchr@2.2.0", Name: "memchr", Version: "2.2.0"},
		{ID: "mime@0.2.6", Name: "mime", Version: "0.2.6"},
		{ID: "modifier@0.1.0", Name: "modifier", Version: "0.1.0"},
		{ID: "mustache@0.9.0", Name: "mustache", Version: "0.9.0"},
		{ID: "nickel@0.11.0", Name: "nickel", Version: "0.11.0"},
		{ID: "num_cpus@1.10.0", Name: "num_cpus", Version: "1.10.0"},
		{ID: "percent-encoding@1.0.1", Name: "percent-encoding", Version: "1.0.1"},
		{ID: "plugin@0.2.6", Name: "plugin", Version: "0.2.6"},
		{ID: "redox_syscall@0.1.54", Name: "redox_syscall", Version: "0.1.54"},
		{ID: "regex@1.1.6", Name: "regex", Version: "1.1.6"},
		{ID: "regex-syntax@0.6.6", Name: "regex-syntax", Version: "0.6.6"},
		{ID: "ryu@0.2.8", Name: "ryu", Version: "0.2.8"},
		{ID: "safemem@0.3.0", Name: "safemem", Version: "0.3.0"},
		{ID: "serde@1.0.91", Name: "serde", Version: "1.0.91"},
		{ID: "serde_json@1.0.39", Name: "serde_json", Version: "1.0.39"},
		{ID: "smallvec@0.6.9", Name: "smallvec", Version: "0.6.9"},
		{ID: "thread_local@0.3.6", Name: "thread_local", Version: "0.3.6"},
		{ID: "time@0.1.42", Name: "time", Version: "0.1.42"},
		{ID: "traitobject@0.1.0", Name: "traitobject", Version: "0.1.0"},
		{ID: "typeable@0.1.2", Name: "typeable", Version: "0.1.2"},
		{ID: "typemap@0.3.3", Name: "typemap", Version: "0.3.3"},
		{ID: "ucd-util@0.1.3", Name: "ucd-util", Version: "0.1.3"},
		{ID: "unicase@1.4.2", Name: "unicase", Version: "1.4.2"},
		{ID: "unicode-bidi@0.3.4", Name: "unicode-bidi", Version: "0.3.4"},
		{ID: "unicode-normalization@0.1.8", Name: "unicode-normalization", Version: "0.1.8"},
		{ID: "unsafe-any@0.4.2", Name: "unsafe-any", Version: "0.4.2"},
		{ID: "url@1.7.2", Name: "url", Version: "1.7.2"},
		{ID: "utf8-ranges@1.0.2", Name: "utf8-ranges", Version: "1.0.2"},
		{ID: "version_check@0.1.5", Name: "version_check", Version: "0.1.5"},
		{ID: "winapi@0.3.7", Name: "winapi", Version: "0.3.7"},
		{ID: "winapi-i686-pc-windows-gnu@0.4.0", Name: "winapi-i686-pc-windows-gnu", Version: "0.4.0"},
		{ID: "winapi-x86_64-pc-windows-gnu@0.4.0", Name: "winapi-x86_64-pc-windows-gnu", Version: "0.4.0"},
	}
)
