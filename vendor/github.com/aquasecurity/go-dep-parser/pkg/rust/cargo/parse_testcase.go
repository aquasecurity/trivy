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
		{Name: "normal", Version: "0.1.0"},
		{Name: "libc", Version: "0.2.54"},
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
		{Name: "many", Version: "0.1.0"},
		{Name: "aho-corasick", Version: "0.7.3"},
		{Name: "autocfg", Version: "0.1.2"},
		{Name: "base64", Version: "0.10.1"},
		{Name: "base64", Version: "0.9.3"},
		{Name: "bitflags", Version: "1.0.4"},
		{Name: "block-buffer", Version: "0.7.3"},
		{Name: "block-padding", Version: "0.1.4"},
		{Name: "byte-tools", Version: "0.3.1"},
		{Name: "byteorder", Version: "1.3.1"},
		{Name: "cc", Version: "1.0.36"},
		{Name: "cfg-if", Version: "0.1.7"},
		{Name: "cloudabi", Version: "0.0.3"},
		{Name: "cookie", Version: "0.11.1"},
		{Name: "devise", Version: "0.2.0"},
		{Name: "devise_codegen", Version: "0.2.0"},
		{Name: "devise_core", Version: "0.2.0"},
		{Name: "digest", Version: "0.8.0"},
		{Name: "fake-simd", Version: "0.1.2"},
		{Name: "fuchsia-cprng", Version: "0.1.1"},
		{Name: "generic-array", Version: "0.12.0"},
		{Name: "handlebars", Version: "1.1.0"},
		{Name: "httparse", Version: "1.3.3"},
		{Name: "hyper", Version: "0.10.16"},
		{Name: "idna", Version: "0.1.5"},
		{Name: "indexmap", Version: "1.0.2"},
		{Name: "isatty", Version: "0.1.9"},
		{Name: "itoa", Version: "0.4.4"},
		{Name: "language-tags", Version: "0.2.2"},
		{Name: "lazy_static", Version: "1.3.0"},
		{Name: "libc", Version: "0.2.54"},
		{Name: "log", Version: "0.3.9"},
		{Name: "log", Version: "0.4.6"},
		{Name: "maplit", Version: "1.0.1"},
		{Name: "matches", Version: "0.1.8"},
		{Name: "memchr", Version: "2.2.0"},
		{Name: "mime", Version: "0.2.6"},
		{Name: "num_cpus", Version: "1.10.0"},
		{Name: "opaque-debug", Version: "0.2.2"},
		{Name: "pear", Version: "0.1.2"},
		{Name: "pear_codegen", Version: "0.1.2"},
		{Name: "percent-encoding", Version: "1.0.1"},
		{Name: "pest", Version: "2.1.1"},
		{Name: "pest_derive", Version: "2.1.0"},
		{Name: "pest_generator", Version: "2.1.0"},
		{Name: "pest_meta", Version: "2.1.1"},
		{Name: "proc-macro2", Version: "0.4.30"},
		{Name: "quick-error", Version: "1.2.2"},
		{Name: "quote", Version: "0.6.12"},
		{Name: "rand", Version: "0.6.5"},
		{Name: "rand_chacha", Version: "0.1.1"},
		{Name: "rand_core", Version: "0.3.1"},
		{Name: "rand_core", Version: "0.4.0"},
		{Name: "rand_hc", Version: "0.1.0"},
		{Name: "rand_isaac", Version: "0.1.1"},
		{Name: "rand_jitter", Version: "0.1.4"},
		{Name: "rand_os", Version: "0.1.3"},
		{Name: "rand_pcg", Version: "0.1.2"},
		{Name: "rand_xorshift", Version: "0.1.1"},
		{Name: "rdrand", Version: "0.4.0"},
		{Name: "redox_syscall", Version: "0.1.54"},
		{Name: "regex", Version: "1.1.6"},
		{Name: "regex-syntax", Version: "0.6.6"},
		{Name: "ring", Version: "0.13.5"},
		{Name: "rocket", Version: "0.4.0"},
		{Name: "rocket_codegen", Version: "0.4.0"},
		{Name: "rocket_http", Version: "0.4.0"},
		{Name: "ryu", Version: "0.2.8"},
		{Name: "safemem", Version: "0.3.0"},
		{Name: "same-file", Version: "1.0.4"},
		{Name: "serde", Version: "1.0.91"},
		{Name: "serde_json", Version: "1.0.39"},
		{Name: "sha-1", Version: "0.8.1"},
		{Name: "smallvec", Version: "0.6.9"},
		{Name: "state", Version: "0.4.1"},
		{Name: "syn", Version: "0.15.34"},
		{Name: "thread_local", Version: "0.3.6"},
		{Name: "time", Version: "0.1.42"},
		{Name: "toml", Version: "0.4.10"},
		{Name: "traitobject", Version: "0.1.0"},
		{Name: "typeable", Version: "0.1.2"},
		{Name: "typenum", Version: "1.10.0"},
		{Name: "ucd-trie", Version: "0.1.1"},
		{Name: "ucd-util", Version: "0.1.3"},
		{Name: "unicase", Version: "1.4.2"},
		{Name: "unicode-bidi", Version: "0.3.4"},
		{Name: "unicode-normalization", Version: "0.1.8"},
		{Name: "unicode-xid", Version: "0.1.0"},
		{Name: "untrusted", Version: "0.6.2"},
		{Name: "url", Version: "1.7.2"},
		{Name: "utf8-ranges", Version: "1.0.2"},
		{Name: "version_check", Version: "0.1.5"},
		{Name: "walkdir", Version: "2.2.7"},
		{Name: "winapi", Version: "0.3.7"},
		{Name: "winapi-i686-pc-windows-gnu", Version: "0.4.0"},
		{Name: "winapi-util", Version: "0.1.2"},
		{Name: "winapi-x86_64-pc-windows-gnu", Version: "0.4.0"},
		{Name: "yansi", Version: "0.4.0"},
		{Name: "yansi", Version: "0.5.0"},
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
		{Name: "web", Version: "0.1.0"},
		{Name: "aho-corasick", Version: "0.7.3"},
		{Name: "base64", Version: "0.9.3"},
		{Name: "byteorder", Version: "1.3.1"},
		{Name: "cfg-if", Version: "0.1.7"},
		{Name: "groupable", Version: "0.2.0"},
		{Name: "httparse", Version: "1.3.3"},
		{Name: "hyper", Version: "0.10.16"},
		{Name: "idna", Version: "0.1.5"},
		{Name: "itoa", Version: "0.4.4"},
		{Name: "language-tags", Version: "0.2.2"},
		{Name: "lazy_static", Version: "1.3.0"},
		{Name: "libc", Version: "0.2.54"},
		{Name: "log", Version: "0.3.9"},
		{Name: "log", Version: "0.4.6"},
		{Name: "matches", Version: "0.1.8"},
		{Name: "memchr", Version: "2.2.0"},
		{Name: "mime", Version: "0.2.6"},
		{Name: "modifier", Version: "0.1.0"},
		{Name: "mustache", Version: "0.9.0"},
		{Name: "nickel", Version: "0.11.0"},
		{Name: "num_cpus", Version: "1.10.0"},
		{Name: "percent-encoding", Version: "1.0.1"},
		{Name: "plugin", Version: "0.2.6"},
		{Name: "redox_syscall", Version: "0.1.54"},
		{Name: "regex", Version: "1.1.6"},
		{Name: "regex-syntax", Version: "0.6.6"},
		{Name: "ryu", Version: "0.2.8"},
		{Name: "safemem", Version: "0.3.0"},
		{Name: "serde", Version: "1.0.91"},
		{Name: "serde_json", Version: "1.0.39"},
		{Name: "smallvec", Version: "0.6.9"},
		{Name: "thread_local", Version: "0.3.6"},
		{Name: "time", Version: "0.1.42"},
		{Name: "traitobject", Version: "0.1.0"},
		{Name: "typeable", Version: "0.1.2"},
		{Name: "typemap", Version: "0.3.3"},
		{Name: "ucd-util", Version: "0.1.3"},
		{Name: "unicase", Version: "1.4.2"},
		{Name: "unicode-bidi", Version: "0.3.4"},
		{Name: "unicode-normalization", Version: "0.1.8"},
		{Name: "unsafe-any", Version: "0.4.2"},
		{Name: "url", Version: "1.7.2"},
		{Name: "utf8-ranges", Version: "1.0.2"},
		{Name: "version_check", Version: "0.1.5"},
		{Name: "winapi", Version: "0.3.7"},
		{Name: "winapi-i686-pc-windows-gnu", Version: "0.4.0"},
		{Name: "winapi-x86_64-pc-windows-gnu", Version: "0.4.0"},
	}
)
