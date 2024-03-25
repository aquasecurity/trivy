# Java
Trivy supports three types of Java scanning: `JAR/WAR/PAR/EAR`, `pom.xml` and `*gradle.lockfile` files.

Each artifact supports the following scanners:

| Artifact         | SBOM | Vulnerability | License |
|------------------|:----:|:-------------:|:-------:|
| JAR/WAR/PAR/EAR  |  ✓   |       ✓       |    -    |
| pom.xml          |  ✓   |       ✓       |    ✓    |
| *gradle.lockfile |  ✓   |       ✓       |    ✓    |

The following table provides an outline of the features Trivy offers.

| Artifact         |    Internet access    | Dev dependencies | [Dependency graph][dependency-graph] | Position |
|------------------|:---------------------:|:----------------:|:------------------------------------:|:--------:|
| JAR/WAR/PAR/EAR  |     Trivy Java DB     |     Include      |                  -                   |    -     |
| pom.xml          | Maven repository [^1] |     Exclude      |                  ✓                   |  ✓[^7]   |
| *gradle.lockfile |           -           |     Exclude      |                  ✓                   |    ✓     |

These may be enabled or disabled depending on the target.
See [here](./index.md) for the detail.

## JAR/WAR/PAR/EAR
To find information about your JAR[^2] file, Trivy parses `pom.properties` and `MANIFEST.MF` files in your JAR[^2] file and takes required properties[^3].

!!! warning "EXPERIMENTAL"
    Finding JARs in `trivy-java-db` is an experimental function.

If those files don't exist or don't contain enough information - Trivy will try to find this JAR[^2] file in [trivy-java-db](https://github.com/aquasecurity/trivy-java-db).
The Java DB will be automatically downloaded/updated when any JAR[^2] file is found.
It is stored in [the cache directory](../../configuration/cache.md#cache-directory).

!!! note
    `trivy-java-db` is enable by default. To disable it - use the `--java-scan-options offline` flag.

Base JAR[^2] may contain inner JARs[^2] within itself.
To find information about these JARs[^2], the same logic is used as for the base JAR[^2].

`table` format only contains the name of root JAR[^2] . To get the full path to inner JARs[^2] use the `json` format.

## pom.xml
Trivy parses your `pom.xml` file and tries to find files with dependencies from these local locations.

- project directory[^4]
- relativePath field[^5]
- local repository directory[^6].

If your machine doesn't have the necessary files - Trivy tries to find the information about these dependencies in the [maven repository](https://repo.maven.apache.org/maven2/).

!!! Note
    Trivy only takes information about packages. We don't take a list of vulnerabilities for packages from the `maven repository`.
    Information about data sources for Java you can see [here](../../scanner/vulnerability.md#data-sources-1).

Trivy supports dependency discovery from [pom repositories][pom-repositories].

Pom repositories are disabled by default.
To enable dependency searching from the `releases` and `snapshots` repositories use the `--java-scan-options releases,snapshots` flag.
!!! note
    Don't forget add `maven-central` option if you need to use pom repositories along with maven central repository (`--java-scan-options releases,snapshots,maven-central`).
    
    Pom repositories have higher priority than maven repository!

You can disable connecting to the maven repository with the `--java-scan-options offline` flag.
The `--java-scan-options offline` flag does not affect the Trivy database.
The vulnerability database will be downloaded anyway.

!!! Warning
    Trivy may skip some dependencies (that were not found on your local machine) when the `--java-scan-options offline` flag is passed.


### maven-invoker-plugin
Typically, the integration tests directory (`**/[src|target]/it/*/pom.xml`) of [maven-invoker-plugin][maven-invoker-plugin] doesn't contain actual `pom.xml` files and should be skipped to avoid noise.

Trivy marks dependencies from these files as the development dependencies and skip them by default.
If you need to show them, use the `--include-dev-deps` flag.


## Gradle.lock
`gradle.lock` files only contain information about used dependencies.

!!!note
    All necessary files are checked locally. Gradle file scanning doesn't require internet access.

### Dependency-tree
!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.
Trivy finds child dependencies from `*.pom` files in the cache[^8] directory.

But there is no reliable way to determine direct dependencies (even using other files).
Therefore, we mark all dependencies as indirect to use logic to guess direct dependencies and build a dependency tree.

### Licenses
Trity also can detect licenses for dependencies.

Make sure that you have cache[^8] directory to find licenses from `*.pom` dependency files.

[^1]: Uses maven repository to get information about dependencies. Internet access required.
[^2]: It means `*.jar`, `*.war`, `*.par` and `*.ear` file
[^3]: `ArtifactID`, `GroupID` and `Version`
[^4]: e.g. when parent pom.xml file has `../pom.xml` path
[^5]: When you use dependency path in `relativePath` field in pom.xml file
[^6]: `/Users/<username>/.m2/repository` (for Linux and Mac) and `C:/Users/<username>/.m2/repository` (for Windows) by default
[^7]: To avoid confusion, Trivy only finds locations for direct dependencies from the base pom.xml file.
[^8]: The supported directories are `$GRADLE_USER_HOME/caches` and `$HOME/.gradle/caches` (`%HOMEPATH%\.gradle\caches` for Windows).

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies
[maven-invoker-plugin]: https://maven.apache.org/plugins/maven-invoker-plugin/usage.html
[pom-repositories]: https://maven.apache.org/settings.html#repositories