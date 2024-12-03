# Ruby

Trivy supports [Bundler][bundler] and [RubyGems][rubygems].
The following scanners are supported for Cargo.

| Package manager | SBOM | Vulnerability | License |
|-----------------|:----:|:-------------:|:-------:|
| Bundler         |  ✓   |       ✓       |    -    |
| RubyGems        |  ✓   |       ✓       |    ✓    |


The following table provides an outline of the features Trivy offers.

| Package manager | File         | Transitive dependencies | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|-----------------|--------------|:-----------------------:|:-----------------|:------------------------------------:|:--------:|
| Bundler         | Gemfile.lock |            ✓            | Included         |                  ✓                   |    ✓     |
| RubyGems        | .gemspec     |            -            | Included         |                  -                   |    -     |


### Bundler
Trivy searches for `Gemfile.lock` to detect dependencies. 


### RubyGems
`.gemspec` files doesn't contains transitive dependencies. You need to scan each `.gemspec` file separately.

[bundler]: https://bundler.io
[rubygems]: https://rubygems.org/
[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies

