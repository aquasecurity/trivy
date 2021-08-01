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
		{"normal", "0.1.0", ""},
		{"libc", "0.2.54", ""},
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
		{"many", "0.1.0", ""},
		{"aho-corasick", "0.7.3", ""},
		{"autocfg", "0.1.2", ""},
		{"base64", "0.10.1", ""},
		{"base64", "0.9.3", ""},
		{"bitflags", "1.0.4", ""},
		{"block-buffer", "0.7.3", ""},
		{"block-padding", "0.1.4", ""},
		{"byte-tools", "0.3.1", ""},
		{"byteorder", "1.3.1", ""},
		{"cc", "1.0.36", ""},
		{"cfg-if", "0.1.7", ""},
		{"cloudabi", "0.0.3", ""},
		{"cookie", "0.11.1", ""},
		{"devise", "0.2.0", ""},
		{"devise_codegen", "0.2.0", ""},
		{"devise_core", "0.2.0", ""},
		{"digest", "0.8.0", ""},
		{"fake-simd", "0.1.2", ""},
		{"fuchsia-cprng", "0.1.1", ""},
		{"generic-array", "0.12.0", ""},
		{"handlebars", "1.1.0", ""},
		{"httparse", "1.3.3", ""},
		{"hyper", "0.10.16", ""},
		{"idna", "0.1.5", ""},
		{"indexmap", "1.0.2", ""},
		{"isatty", "0.1.9", ""},
		{"itoa", "0.4.4", ""},
		{"language-tags", "0.2.2", ""},
		{"lazy_static", "1.3.0", ""},
		{"libc", "0.2.54", ""},
		{"log", "0.3.9", ""},
		{"log", "0.4.6", ""},
		{"maplit", "1.0.1", ""},
		{"matches", "0.1.8", ""},
		{"memchr", "2.2.0", ""},
		{"mime", "0.2.6", ""},
		{"num_cpus", "1.10.0", ""},
		{"opaque-debug", "0.2.2", ""},
		{"pear", "0.1.2", ""},
		{"pear_codegen", "0.1.2", ""},
		{"percent-encoding", "1.0.1", ""},
		{"pest", "2.1.1", ""},
		{"pest_derive", "2.1.0", ""},
		{"pest_generator", "2.1.0", ""},
		{"pest_meta", "2.1.1", ""},
		{"proc-macro2", "0.4.30", ""},
		{"quick-error", "1.2.2", ""},
		{"quote", "0.6.12", ""},
		{"rand", "0.6.5", ""},
		{"rand_chacha", "0.1.1", ""},
		{"rand_core", "0.3.1", ""},
		{"rand_core", "0.4.0", ""},
		{"rand_hc", "0.1.0", ""},
		{"rand_isaac", "0.1.1", ""},
		{"rand_jitter", "0.1.4", ""},
		{"rand_os", "0.1.3", ""},
		{"rand_pcg", "0.1.2", ""},
		{"rand_xorshift", "0.1.1", ""},
		{"rdrand", "0.4.0", ""},
		{"redox_syscall", "0.1.54", ""},
		{"regex", "1.1.6", ""},
		{"regex-syntax", "0.6.6", ""},
		{"ring", "0.13.5", ""},
		{"rocket", "0.4.0", ""},
		{"rocket_codegen", "0.4.0", ""},
		{"rocket_http", "0.4.0", ""},
		{"ryu", "0.2.8", ""},
		{"safemem", "0.3.0", ""},
		{"same-file", "1.0.4", ""},
		{"serde", "1.0.91", ""},
		{"serde_json", "1.0.39", ""},
		{"sha-1", "0.8.1", ""},
		{"smallvec", "0.6.9", ""},
		{"state", "0.4.1", ""},
		{"syn", "0.15.34", ""},
		{"thread_local", "0.3.6", ""},
		{"time", "0.1.42", ""},
		{"toml", "0.4.10", ""},
		{"traitobject", "0.1.0", ""},
		{"typeable", "0.1.2", ""},
		{"typenum", "1.10.0", ""},
		{"ucd-trie", "0.1.1", ""},
		{"ucd-util", "0.1.3", ""},
		{"unicase", "1.4.2", ""},
		{"unicode-bidi", "0.3.4", ""},
		{"unicode-normalization", "0.1.8", ""},
		{"unicode-xid", "0.1.0", ""},
		{"untrusted", "0.6.2", ""},
		{"url", "1.7.2", ""},
		{"utf8-ranges", "1.0.2", ""},
		{"version_check", "0.1.5", ""},
		{"walkdir", "2.2.7", ""},
		{"winapi", "0.3.7", ""},
		{"winapi-i686-pc-windows-gnu", "0.4.0", ""},
		{"winapi-util", "0.1.2", ""},
		{"winapi-x86_64-pc-windows-gnu", "0.4.0", ""},
		{"yansi", "0.4.0", ""},
		{"yansi", "0.5.0", ""},
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
		{"web", "0.1.0", ""},
		{"aho-corasick", "0.7.3", ""},
		{"base64", "0.9.3", ""},
		{"byteorder", "1.3.1", ""},
		{"cfg-if", "0.1.7", ""},
		{"groupable", "0.2.0", ""},
		{"httparse", "1.3.3", ""},
		{"hyper", "0.10.16", ""},
		{"idna", "0.1.5", ""},
		{"itoa", "0.4.4", ""},
		{"language-tags", "0.2.2", ""},
		{"lazy_static", "1.3.0", ""},
		{"libc", "0.2.54", ""},
		{"log", "0.3.9", ""},
		{"log", "0.4.6", ""},
		{"matches", "0.1.8", ""},
		{"memchr", "2.2.0", ""},
		{"mime", "0.2.6", ""},
		{"modifier", "0.1.0", ""},
		{"mustache", "0.9.0", ""},
		{"nickel", "0.11.0", ""},
		{"num_cpus", "1.10.0", ""},
		{"percent-encoding", "1.0.1", ""},
		{"plugin", "0.2.6", ""},
		{"redox_syscall", "0.1.54", ""},
		{"regex", "1.1.6", ""},
		{"regex-syntax", "0.6.6", ""},
		{"ryu", "0.2.8", ""},
		{"safemem", "0.3.0", ""},
		{"serde", "1.0.91", ""},
		{"serde_json", "1.0.39", ""},
		{"smallvec", "0.6.9", ""},
		{"thread_local", "0.3.6", ""},
		{"time", "0.1.42", ""},
		{"traitobject", "0.1.0", ""},
		{"typeable", "0.1.2", ""},
		{"typemap", "0.3.3", ""},
		{"ucd-util", "0.1.3", ""},
		{"unicase", "1.4.2", ""},
		{"unicode-bidi", "0.3.4", ""},
		{"unicode-normalization", "0.1.8", ""},
		{"unsafe-any", "0.4.2", ""},
		{"url", "1.7.2", ""},
		{"utf8-ranges", "1.0.2", ""},
		{"version_check", "0.1.5", ""},
		{"winapi", "0.3.7", ""},
		{"winapi-i686-pc-windows-gnu", "0.4.0", ""},
		{"winapi-x86_64-pc-windows-gnu", "0.4.0", ""},
	}
)
