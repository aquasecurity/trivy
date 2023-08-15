# Elixir

Trivy supports [Hex][hex] for [Elixir][elixir].

The following scanners are supported.

| Package manager | SBOM  | Vulnerability | License |
|-----------------| :---: | :-----------: |:-------:|
| [hex][hex]        |   ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.


| Package manager | File         | Transitive dependencies | Dev dependencies | Dependency graph | Position |
|-----------------|--------------|:-----------------------:|:----------------:|:----------------:|:--------:|
| [hex][hex]      | mix.lock[^1] |            ✓            |     Excluded     |        -         |    ✓     |

## Hex
In order to detect dependencies, Trivy searches for `mix.lock`[^1].

[Configure](https://hexdocs.pm/mix/Mix.Project.html#module-configuration) your project to use `mix.lock`[^1] file.

[elixir]: https://elixir-lang.org/
[hex]: https://hex.pm/

[^1]: `mix.lock` is default name. To scan a custom filename use [file-patterns](../../configuration/skipping.md#file-patterns)