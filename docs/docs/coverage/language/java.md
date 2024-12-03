# Java
Trivy supports four types of Java scanning: `JAR/WAR/PAR/EAR`, `pom.xml`, `*gradle.lockfile` and `*.sbt.lock` files.

Each artifact supports the following scanners:

| Artifact         | SBOM | Vulnerability | License |
|------------------|:----:|:-------------:|:-------:|
| JAR/WAR/PAR/EAR  |  ✓   |       ✓       |    -    |
| pom.xml          |  ✓   |       ✓       |    ✓    |
| *gradle.lockfile |  ✓   |       ✓       |    ✓    |
| *.sbt.lock       |  ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Artifact         |    Internet access    | Dev dependencies | [Dependency graph][dependency-graph] | Position | [Detection Priority][detection-priority] |
|------------------|:---------------------:|:----------------:|:------------------------------------:|:--------:|:----------------------------------------:|
| JAR/WAR/PAR/EAR  |     Trivy Java DB     |     Include      |                  -                   |    -     |                Not needed                |
| pom.xml          | Maven repository [^1] |     Exclude      |                  ✓                   |  ✓[^7]   |                    -                     |
| *gradle.lockfile |           -           |     Exclude      |                  ✓                   |    ✓     |                Not needed                |
| *.sbt.lock       |           -           |     Exclude      |                  -                   |    ✓     |                Not needed                |

These may be enabled or disabled depending on the target.
See [here](./index.md) for the detail.

## JAR/WAR/PAR/EAR
To find information about your JAR[^2] file, Trivy parses `pom.properties` and `MANIFEST.MF` files in your JAR[^2] file and takes required properties[^3].

If those files don't exist or don't contain enough information - Trivy will try to find this JAR[^2] file in [trivy-java-db](https://github.com/aquasecurity/trivy-java-db).
The Java DB will be automatically downloaded/updated when any JAR[^2] file is found.
It is stored in [the cache directory](../../configuration/cache.md#cache-directory).

!!! warning "EXPERIMENTAL"
    Finding JARs in `trivy-java-db` is an experimental function.

Base JAR[^2] may contain inner JARs[^2] within itself.
To find information about these JARs[^2], the same logic is used as for the base JAR[^2].

`table` format only contains the name of root JAR[^2] . To get the full path to inner JARs[^2] use the `json` format.

## pom.xml
Trivy parses your `pom.xml` file and tries to find files with dependencies from these local locations.

- project directory[^4]
- relativePath field[^5]
- local repository directory[^6].

### remote repositories
If your machine doesn't have the necessary files - Trivy tries to find the information about these dependencies in the remote repositories:

- [repositories from pom files][maven-pom-repos]
- [maven central repository][maven-central]

Trivy reproduces Maven's repository selection and priority:

- for snapshot artifacts:
    - check only snapshot repositories from pom files (if exists)
- for other artifacts:
    - check release repositories from pom files (if exists)
    - check [maven central][maven-central]

!!! Note
    Trivy only takes information about packages. We don't take a list of vulnerabilities for packages from the `maven repository`.
    Information about data sources for Java you can see [here](../../scanner/vulnerability.md#langpkg-data-sources).

You can disable connecting to the maven repository with the `--offline-scan` flag.
The `--offline-scan` flag does not affect the Trivy database.
The vulnerability database will be downloaded anyway.

!!! Warning
    Trivy may skip some dependencies (that were not found on your local machine) when the `--offline-scan` flag is passed.

### supported scopes
Trivy only scans `import`, `compile`, `runtime` and empty [maven scopes][maven-scopes]. Other scopes and `Optional` dependencies are not currently being analyzed.

### empty dependency version
There are cases when Trivy cannot determine the version of dependencies:

- Unable to determine the version from the parent because the parent is not reachable;
- The dependency uses a [hard requirement][version-requirement] with more than one version.

In these cases, Trivy uses an empty version for the dependency.

!!! Warning
    Trivy doesn't detect child dependencies for dependencies without a version.

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


## SBT

`build.sbt.lock` files only contain information about used dependencies. This requires a lockfile generated using the
[sbt-dependency-lock][sbt-dependency-lock] plugin.

!!!note
    All necessary files are checked locally. SBT file scanning doesn't require internet access.

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
[maven-central]: https://repo.maven.apache.org/maven2/
[maven-pom-repos]: https://maven.apache.org/settings.html#repositories
[maven-scopes]: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope
[sbt-dependency-lock]: https://stringbean.github.io/sbt-dependency-lock
[detection-priority]: ../../scanner/vulnerability.md#detection-priority
[version-requirement]: https://maven.apache.org/pom.html#dependency-version-requirement-specification
