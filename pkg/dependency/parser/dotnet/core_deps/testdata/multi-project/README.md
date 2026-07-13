# Multi-project fixture

This fixture verifies parsing a published application with project references:

```text
Web -> Api -> Data
```

`Web` also references `Newtonsoft.Json` directly. To regenerate `Web.deps.json`
with the .NET 10 SDK, run from this directory:

```shell
(
  set -euo pipefail
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  cp -R Web Api Data "$tmp_dir"
  dotnet publish "$tmp_dir/Web/Web.csproj" \
    --output "$tmp_dir/publish" \
    -m:1 \
    -p:UseSharedCompilation=false
  cp "$tmp_dir/publish/Web.deps.json" Web.deps.json
)
```

The command builds in a temporary directory so it does not leave `bin` or `obj`
directories in the fixture.
