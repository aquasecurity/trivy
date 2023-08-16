# Java
Trivy supports three types of Java scanning: `JAR/WAR/PAR/EAR`, `pom.xml` and `*gradle.lockfile` files.

Each artifact supports the following scanners:

| Artifact         | SBOM  | Vulnerability | License |
| ---------------- | :---: | :-----------: | :-----: |
| JAR/WAR/PAR/EAR  |   ✓   |       ✓       |    -    |
| pom.xml          |   ✓   |       ✓       |    ✓    |
| *gradle.lockfile |   ✓   |       ✓       |    -    |

The following table provides an outline of the features Trivy offers.

| Artifact         |    Internet access    | Dev dependencies | [Dependency graph][dependency-graph] |
|------------------|:---------------------:|:----------------:|:------------------------------------:|
| JAR/WAR/PAR/EAR  |     Trivy Java DB     |     Include      |                  -                   |
| pom.xml          | Maven repository [^1] |     Exclude      |                  -                   |
| *gradle.lockfile |           -           |     Exclude      |                  -                   |

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

If your machine doesn't have the necessary files - Trivy tries to find the information about these dependencies in the [maven repository](https://repo.maven.apache.org/maven2/).

!!! Note
    Trivy only takes information about packages. We don't take a list of vulnerabilities for packages from the `maven repository`.
    Information about data sources for Java you can see [here](../../scanner/vulnerability.md#data-sources_1).

You can disable connecting to the maven repository with the `--offline-scan` flag.
The `--offline-scan` flag does not affect the Trivy database.
The vulnerability database will be downloaded anyway.

!!! Warning
    Trivy may skip some dependencies (that were not found on your local machine) when the `--offline-scan` flag is passed.

## Gradle.lock
`gradle.lock` files contain all necessary information about used dependencies.
Trivy simply parses the file, extract dependencies, and finds vulnerabilities for them.
It doesn't require the internet access.

[^1]: https://github.com/aquasecurity/trivy-java-db
[^1]: Uses maven repository to get information about dependencies. Internet access required.
[^2]: It means `*.jar`, `*.war`, `*.par` and `*.ear` file
[^3]: `ArtifactID`, `GroupID` and `Version`
[^4]: e.g. when parent pom.xml file has `../pom.xml` path
[^5]: When you use dependency path in `relativePath` field in pom.xml file
[^6]: `/Users/<username>/.m2/repository` (for Linux and Mac) and `C:/Users/<username>/.m2/repository` (for Windows) by default

[dependency-graph]: ../../configuration/reporting.md#show-origins-of-vulnerable-dependencies