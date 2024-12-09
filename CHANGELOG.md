# Changelog

## [0.58.0](https://github.com/aquasecurity/trivy/compare/v0.57.0...v0.58.0) (2024-12-02)


### Features

* add `workspaceRelationship` ([#7889](https://github.com/aquasecurity/trivy/issues/7889)) ([d622ca2](https://github.com/aquasecurity/trivy/commit/d622ca2b1fe40a0eb588478ba9e15d3bd8471a78))
* add cvss v4 score and vector in scan response ([#7968](https://github.com/aquasecurity/trivy/issues/7968)) ([e0f2054](https://github.com/aquasecurity/trivy/commit/e0f2054f9d12dce87e8a0226350f6317f7167195))
* **go:** construct dependencies in the parser ([#7973](https://github.com/aquasecurity/trivy/issues/7973)) ([bcdc0bb](https://github.com/aquasecurity/trivy/commit/bcdc0bbf1f63777ff79d3ecadb8d4f916f376b7d))
* **go:** construct dependencies of `go.mod` main module in the parser ([#7977](https://github.com/aquasecurity/trivy/issues/7977)) ([5448ba2](https://github.com/aquasecurity/trivy/commit/5448ba2a5c1ee36cbcf74ee1c2e83409092c5715))
* **k8s:** add default commands for unknown platform ([#7863](https://github.com/aquasecurity/trivy/issues/7863)) ([b1c7f55](https://github.com/aquasecurity/trivy/commit/b1c7f5516fc39c6cbb76cbeae5c8677ccc9ce5dd))
* **misconf:** log causes of HCL file parsing errors ([#7634](https://github.com/aquasecurity/trivy/issues/7634)) ([e9a899a](https://github.com/aquasecurity/trivy/commit/e9a899a3cfe41a622202808a0241b7f40b54d338))
* **oracle:** add `flavors` support ([#7858](https://github.com/aquasecurity/trivy/issues/7858)) ([b9b383e](https://github.com/aquasecurity/trivy/commit/b9b383eb2714e88357af75900c856db2900b83ec))
* **secret:** Add built-in secrets rules for Private Packagist ([#7826](https://github.com/aquasecurity/trivy/issues/7826)) ([132d9df](https://github.com/aquasecurity/trivy/commit/132d9dfa19a8835c94f332c6939ab7f64641ee5f))
* **suse:** Align SUSE/OpenSUSE OS Identifiers ([#7965](https://github.com/aquasecurity/trivy/issues/7965)) ([45d3b40](https://github.com/aquasecurity/trivy/commit/45d3b40044202dec91384847ce2b50a7271f5977))
* Update registry fallbacks ([#7679](https://github.com/aquasecurity/trivy/issues/7679)) ([5ba9a83](https://github.com/aquasecurity/trivy/commit/5ba9a83a447c4f9e577ae6235c315df71f50b452))


### Bug Fixes

* **alpine:** add `UID` for removed packages ([#7887](https://github.com/aquasecurity/trivy/issues/7887)) ([07915da](https://github.com/aquasecurity/trivy/commit/07915da4816d4d9ec8a6c5e4cba17be2a0f4ad65))
* **aws:** change CPU and Memory type of ContainerDefinition to a string ([#7995](https://github.com/aquasecurity/trivy/issues/7995)) ([aeeba70](https://github.com/aquasecurity/trivy/commit/aeeba70d15c11443d9fe7c26f90fc7d9dcc7f92c))
* **cli:** Handle empty ignore files more gracefully ([#7962](https://github.com/aquasecurity/trivy/issues/7962)) ([4cfb2a9](https://github.com/aquasecurity/trivy/commit/4cfb2a97b27923182ab45c178544542ec65981d4))
* **debian:** infinite loop ([#7928](https://github.com/aquasecurity/trivy/issues/7928)) ([d982e6a](https://github.com/aquasecurity/trivy/commit/d982e6ab89967629f71ec09100cdc61e30a27c63))
* **fs:** add missing defered Cleanup() call to post analyzer fs ([#7882](https://github.com/aquasecurity/trivy/issues/7882)) ([ab32297](https://github.com/aquasecurity/trivy/commit/ab32297e0a8220a427fa330025f8625281e02275))
* Improve version comparisons when build identifiers are present ([#7873](https://github.com/aquasecurity/trivy/issues/7873)) ([eda4d76](https://github.com/aquasecurity/trivy/commit/eda4d7660d8908705bc08a6edc55d8144d02806a))
* **k8s:** check all results for vulnerabilities ([#7946](https://github.com/aquasecurity/trivy/issues/7946)) ([797b36f](https://github.com/aquasecurity/trivy/commit/797b36fbad90b8e7f04e16e2cf08d6bdc0255ac7))
* **misconf:** do not erase variable type for child modules ([#7941](https://github.com/aquasecurity/trivy/issues/7941)) ([de3b7ea](https://github.com/aquasecurity/trivy/commit/de3b7ea24c282bce22ce9cacb49a43d8d90e2bde))
* **misconf:** handle null properties in CloudFormation templates ([#7813](https://github.com/aquasecurity/trivy/issues/7813)) ([99b2db3](https://github.com/aquasecurity/trivy/commit/99b2db3978562689cef956a71281abb84ff0ce47))
* **misconf:** load full Terraform module ([#7925](https://github.com/aquasecurity/trivy/issues/7925)) ([fbc42a0](https://github.com/aquasecurity/trivy/commit/fbc42a04ea24e2246f81491434a965846d55ed69))
* **misconf:** properly resolve local Terraform cache ([#7983](https://github.com/aquasecurity/trivy/issues/7983)) ([fe3a897](https://github.com/aquasecurity/trivy/commit/fe3a8971b6697d896c1ec30b5326a10c20349d14))
* **misconf:** Update trivy-checks default repo to `mirror.gcr.io` ([#7953](https://github.com/aquasecurity/trivy/issues/7953)) ([9988147](https://github.com/aquasecurity/trivy/commit/9988147b8b0e463464fe494122bfcc66ccdf04e0))
* **misconf:** wrap AWS EnvVar to iac types ([#7407](https://github.com/aquasecurity/trivy/issues/7407)) ([54130dc](https://github.com/aquasecurity/trivy/commit/54130dcc1d775506d34b83a558952176fc549914))
* **redhat:** don't return error if `root/buildinfo/content_manifests/` contains files that are not `contentSets` files ([#7912](https://github.com/aquasecurity/trivy/issues/7912)) ([38775a5](https://github.com/aquasecurity/trivy/commit/38775a5ed985eefe2b410e72407c454cdad3d075))
* **report:** handle `git@github.com` schema for misconfigs in `sarif` report ([#7898](https://github.com/aquasecurity/trivy/issues/7898)) ([19aea4b](https://github.com/aquasecurity/trivy/commit/19aea4b01f3ce5a3cd05d5a1091da5b0b3ba4af6))
* **sbom:** Fixes for Programming Language Vulnerabilities and SBOM Package Maintainer Details ([#7871](https://github.com/aquasecurity/trivy/issues/7871)) ([461a68a](https://github.com/aquasecurity/trivy/commit/461a68afd60b77dd67e91047b3b4d558fa5bd2ec))
* **terraform:** set null value as fallback for missing variables ([#7669](https://github.com/aquasecurity/trivy/issues/7669)) ([611558e](https://github.com/aquasecurity/trivy/commit/611558e4ce61818330118684274534f26b1fda99))

## [0.57.0](https://github.com/aquasecurity/trivy/compare/v0.56.0...v0.57.0) (2024-10-31)


### ⚠ BREAKING CHANGES

* **k8s:** support k8s multi container ([#7444](https://github.com/aquasecurity/trivy/issues/7444))

### Features

* add end of life date for Ubuntu 24.10 ([#7787](https://github.com/aquasecurity/trivy/issues/7787)) ([ad3c09e](https://github.com/aquasecurity/trivy/commit/ad3c09e006e134f3c5b879ffc34ce9895a8c860f))
* **cli:** add `trivy auth` ([#7664](https://github.com/aquasecurity/trivy/issues/7664)) ([27117f8](https://github.com/aquasecurity/trivy/commit/27117f81d52483c3ceec56fe56ac298e242fbc9a))
* **cli:** error out when ignore file cannot be found ([#7624](https://github.com/aquasecurity/trivy/issues/7624)) ([cb0b3a9](https://github.com/aquasecurity/trivy/commit/cb0b3a9279b31810ecd686a385e5140e567ce86f))
* **cli:** rename `trivy auth` to `trivy registry` ([#7727](https://github.com/aquasecurity/trivy/issues/7727)) ([633a7ab](https://github.com/aquasecurity/trivy/commit/633a7abeea4287899392a24f2705f96dfeb7e312))
* **cyclonedx:** add file checksums to `CycloneDX` reports ([#7507](https://github.com/aquasecurity/trivy/issues/7507)) ([c225883](https://github.com/aquasecurity/trivy/commit/c225883649f58128a99fa2c1cef327d0e57940be))
* **db:** append errors ([#7843](https://github.com/aquasecurity/trivy/issues/7843)) ([5e78b6c](https://github.com/aquasecurity/trivy/commit/5e78b6c12fb5740c12dedeea3d335d48ec2f752b))
* **misconf:** export unresolvable field of IaC types to Rego ([#7765](https://github.com/aquasecurity/trivy/issues/7765)) ([9514148](https://github.com/aquasecurity/trivy/commit/9514148767865baddd73a49245385574927f7a74))
* **misconf:** public network support for Azure Storage Account ([#7601](https://github.com/aquasecurity/trivy/issues/7601)) ([ad91412](https://github.com/aquasecurity/trivy/commit/ad914123c4d203af1e1da6b7e2d3e49d9d3831d8))
* **misconf:** Show misconfig ID in output ([#7762](https://github.com/aquasecurity/trivy/issues/7762)) ([f75c0d1](https://github.com/aquasecurity/trivy/commit/f75c0d1f0069d4856cb4826d6049f32c5b9409d9))
* **misconf:** ssl_mode support for GCP SQL DB instance ([#7564](https://github.com/aquasecurity/trivy/issues/7564)) ([2eaa17e](https://github.com/aquasecurity/trivy/commit/2eaa17e0717940b27a79050e2efd9213b71178c9))
* **parser:** ignore white space in pom.xml files ([#7747](https://github.com/aquasecurity/trivy/issues/7747)) ([a7baa93](https://github.com/aquasecurity/trivy/commit/a7baa93b00b8636aa097e64cdb8eed97dbd68511))
* **report:** update gitlab template to populate operating_system value ([#7735](https://github.com/aquasecurity/trivy/issues/7735)) ([c0d79fa](https://github.com/aquasecurity/trivy/commit/c0d79fa09e645f3a3dbff878e393b8631fb17b64))


### Bug Fixes

* **cli:** `clean --all` deletes only relevant dirs ([#7704](https://github.com/aquasecurity/trivy/issues/7704)) ([672e886](https://github.com/aquasecurity/trivy/commit/672e886aed152ae0f09a16941706746f3053ca94))
* **cli:** add config name to skip-policy-update alias ([#7820](https://github.com/aquasecurity/trivy/issues/7820)) ([b661d68](https://github.com/aquasecurity/trivy/commit/b661d680ff0372c8e4beea0db13bf69d6a2203a8))
* **db:** fix javadb downloading error handling ([#7642](https://github.com/aquasecurity/trivy/issues/7642)) ([2c87f0c](https://github.com/aquasecurity/trivy/commit/2c87f0cb794acd77446a273582ba1a45b9f18980))
* enable usestdlibvars linter ([#7770](https://github.com/aquasecurity/trivy/issues/7770)) ([57e24aa](https://github.com/aquasecurity/trivy/commit/57e24aa85382f749df7f673e241caaf3fcbb45cb))
* **go:** Do not trim v prefix from versions in Go Mod Analyzer ([#7733](https://github.com/aquasecurity/trivy/issues/7733)) ([e872ec0](https://github.com/aquasecurity/trivy/commit/e872ec006c0745a5a142728af0096c6d6bb9ddf3))
* **helm:** properly handle multiple archived dependencies ([#7782](https://github.com/aquasecurity/trivy/issues/7782)) ([6fab88d](https://github.com/aquasecurity/trivy/commit/6fab88dd56c257ef2cc63b617c2a5decb1c4cf98))
* **java:** correctly inherit `version` and `scope` from upper/root `depManagement` and `dependencies` into parents ([#7541](https://github.com/aquasecurity/trivy/issues/7541)) ([778df82](https://github.com/aquasecurity/trivy/commit/778df828eaad9827cb833c6285058a33aa2b83ca))
* **k8s:** skip resources without misconfigs ([#7797](https://github.com/aquasecurity/trivy/issues/7797)) ([7882776](https://github.com/aquasecurity/trivy/commit/78827768a612ab305bf9c55409ce76d6774302a5))
* **k8s:** support k8s multi container ([#7444](https://github.com/aquasecurity/trivy/issues/7444)) ([c434775](https://github.com/aquasecurity/trivy/commit/c4347759234dcb5f372b07f92fb4230ef391d710))
* **k8s:** support kubernetes v1.31 ([#7810](https://github.com/aquasecurity/trivy/issues/7810)) ([7a4f4d8](https://github.com/aquasecurity/trivy/commit/7a4f4d8b12996687f3095a2042cdf2f5985332c9))
* **license:** fix license normalization for Universal Permissive License ([#7766](https://github.com/aquasecurity/trivy/issues/7766)) ([f6acdf7](https://github.com/aquasecurity/trivy/commit/f6acdf713991f8ffdbe765178fcb8a9cde433cba))
* **misconf:** change default ACL of digitalocean_spaces_bucket to private ([#7577](https://github.com/aquasecurity/trivy/issues/7577)) ([9da84f5](https://github.com/aquasecurity/trivy/commit/9da84f54fadbe6ad0d73983952e945ed63b666f3))
* **misconf:** check if property is not nil before conversion ([#7578](https://github.com/aquasecurity/trivy/issues/7578)) ([c8c14d3](https://github.com/aquasecurity/trivy/commit/c8c14d36245623019f29d258f813d2325f7490f7))
* **misconf:** fix for Azure Storage Account network acls adaptation ([#7602](https://github.com/aquasecurity/trivy/issues/7602)) ([35fd018](https://github.com/aquasecurity/trivy/commit/35fd018ae7ad86823f114f0ac2f1376726aee444))
* **misconf:** properly expand dynamic blocks ([#7612](https://github.com/aquasecurity/trivy/issues/7612)) ([8d5dbc9](https://github.com/aquasecurity/trivy/commit/8d5dbc9fec3569b22ed81a03c40eaf732768718b))
* **redhat:** include arch in PURL qualifiers ([#7654](https://github.com/aquasecurity/trivy/issues/7654)) ([a585e95](https://github.com/aquasecurity/trivy/commit/a585e95f3398631d9ad10505c5ff642fde21aef7))
* **repo:** `git clone` output to Stderr ([#7561](https://github.com/aquasecurity/trivy/issues/7561)) ([fdf203c](https://github.com/aquasecurity/trivy/commit/fdf203cd209aeb40f454bd12d121a54d6ed7a542))
* **report:** Fix invalid URI in SARIF report ([#7645](https://github.com/aquasecurity/trivy/issues/7645)) ([015bb88](https://github.com/aquasecurity/trivy/commit/015bb885ac414b91201fa9791eead395d878149c))
* **sbom:** add options for DBs in private registries ([#7660](https://github.com/aquasecurity/trivy/issues/7660)) ([1f2e91b](https://github.com/aquasecurity/trivy/commit/1f2e91b02b3606dd11963002a8cfac7962f3478f))
* **sbom:** use `Annotation` instead of `AttributionTexts` for `SPDX` formats ([#7811](https://github.com/aquasecurity/trivy/issues/7811)) ([f2bb9c6](https://github.com/aquasecurity/trivy/commit/f2bb9c6227743dd61f44eb591d4b15192fe110c6))

## [0.56.0](https://github.com/aquasecurity/trivy/compare/v0.55.0...v0.56.0) (2024-10-03)


### Features

* **java:** add empty versions if `pom.xml` dependency versions can't be detected ([#7520](https://github.com/aquasecurity/trivy/issues/7520)) ([b836232](https://github.com/aquasecurity/trivy/commit/b8362321adb2af220830c5de31c29978423d47da))
* **license:** improve license normalization ([#7131](https://github.com/aquasecurity/trivy/issues/7131)) ([6472e3c](https://github.com/aquasecurity/trivy/commit/6472e3c9da2a8e7ba41598a45c80df8f18e57d4c))
* **misconf:** add ability to disable checks by ID ([#7536](https://github.com/aquasecurity/trivy/issues/7536)) ([ef0a27d](https://github.com/aquasecurity/trivy/commit/ef0a27d515ff80762bf1959d44a8bde017ae06ec))
* **misconf:** Register checks only when needed ([#7435](https://github.com/aquasecurity/trivy/issues/7435)) ([f768d3a](https://github.com/aquasecurity/trivy/commit/f768d3a767a99a86b0372f19d9f49a2de35dbe59))
* **misconf:** Support `--skip-*` for all included modules  ([#7579](https://github.com/aquasecurity/trivy/issues/7579)) ([c0e8da3](https://github.com/aquasecurity/trivy/commit/c0e8da3828e9d3a0b30d1f6568037db8dc827765))
* **secret:** enhance secret scanning for python binary files ([#7223](https://github.com/aquasecurity/trivy/issues/7223)) ([60725f8](https://github.com/aquasecurity/trivy/commit/60725f879ba014c5c57583db6afc290b78facae8))
* support multiple DB repositories for vulnerability and Java DB ([#7605](https://github.com/aquasecurity/trivy/issues/7605)) ([3562529](https://github.com/aquasecurity/trivy/commit/3562529ddfb26d301311ed450c192e17011353df))
* support RPM archives ([#7628](https://github.com/aquasecurity/trivy/issues/7628)) ([69bf7e0](https://github.com/aquasecurity/trivy/commit/69bf7e00ea5ab483692db830fdded26a31f03183))
* **suse:** added SUSE Linux Enterprise Micro support ([#7294](https://github.com/aquasecurity/trivy/issues/7294)) ([efdb68d](https://github.com/aquasecurity/trivy/commit/efdb68d3b9ddf9dfaf45ea5855b31c43a4366bab))


### Bug Fixes

* allow access to '..' in mapfs ([#7575](https://github.com/aquasecurity/trivy/issues/7575)) ([a8fbe46](https://github.com/aquasecurity/trivy/commit/a8fbe46119adbd89f827a75c75b9e97d392f1842))
* **db:** check `DownloadedAt` for `trivy-java-db` ([#7592](https://github.com/aquasecurity/trivy/issues/7592)) ([13ef3e7](https://github.com/aquasecurity/trivy/commit/13ef3e7d62ba2bcb3a04d7b44f79b1299674b480))
* **java:** use `dependencyManagement` from root/child pom's for dependencies from parents ([#7497](https://github.com/aquasecurity/trivy/issues/7497)) ([5442949](https://github.com/aquasecurity/trivy/commit/54429497e7d6a87eac236771d4efb8a5a7faaac5))
* **license:** stop spliting a long license text ([#7336](https://github.com/aquasecurity/trivy/issues/7336)) ([4926da7](https://github.com/aquasecurity/trivy/commit/4926da79de901fba73819d71845ec0355b68ae0f))
* **misconf:** Disable deprecated checks by default ([#7632](https://github.com/aquasecurity/trivy/issues/7632)) ([82e2adc](https://github.com/aquasecurity/trivy/commit/82e2adc6f8e68d0cc0021031170c2adb60d213ba))
* **misconf:** disable DS016 check for image history analyzer ([#7540](https://github.com/aquasecurity/trivy/issues/7540)) ([de40df9](https://github.com/aquasecurity/trivy/commit/de40df9408d6d856a3ad384ec9f086edce3aa382))
* **misconf:** escape all special sequences ([#7558](https://github.com/aquasecurity/trivy/issues/7558)) ([ea0cf03](https://github.com/aquasecurity/trivy/commit/ea0cf0379aff0348fde87356dab37947800fc1b6))
* **misconf:** Fix logging typo ([#7473](https://github.com/aquasecurity/trivy/issues/7473)) ([56db43c](https://github.com/aquasecurity/trivy/commit/56db43c24f4f6be92891be85faaf9492cad516ac))
* **misconf:** Fixed scope for China Cloud ([#7560](https://github.com/aquasecurity/trivy/issues/7560)) ([37d549e](https://github.com/aquasecurity/trivy/commit/37d549e5b86a1c5dce6710fbfd2310aec9abe949))
* **misconf:** not to warn about missing selectors of libraries ([#7638](https://github.com/aquasecurity/trivy/issues/7638)) ([fcaea74](https://github.com/aquasecurity/trivy/commit/fcaea740808d5784c120e5c5d65f5f94e1d931d4))
* **oracle:** Update EOL date for Oracle 7 ([#7480](https://github.com/aquasecurity/trivy/issues/7480)) ([dd0a64a](https://github.com/aquasecurity/trivy/commit/dd0a64a1cf0cd76e6f81e3ff55fa6ccb95ce3c3d))
* **report:** change a receiver of MarshalJSON ([#7483](https://github.com/aquasecurity/trivy/issues/7483)) ([927c6e0](https://github.com/aquasecurity/trivy/commit/927c6e0c9d4d4a3f1be00f0f661c1d18325d9440))
* **report:** fix error with unmarshal of `ExperimentalModifiedFindings` ([#7463](https://github.com/aquasecurity/trivy/issues/7463)) ([7ff9aff](https://github.com/aquasecurity/trivy/commit/7ff9aff2739b2eee4a98175b98914795e4077060))
* **sbom:** export bom-ref when converting a package to a component ([#7340](https://github.com/aquasecurity/trivy/issues/7340)) ([5dd94eb](https://github.com/aquasecurity/trivy/commit/5dd94ebc1ffe3f1df511dee6381f92a5daefadf2))
* **sbom:** parse type `framework` as `library` when unmarshalling `CycloneDX` files ([#7527](https://github.com/aquasecurity/trivy/issues/7527)) ([aeb7039](https://github.com/aquasecurity/trivy/commit/aeb7039d7ce090e243d29f0bf16c9e4e24252a01))
* **secret:** change grafana token regex to find them without unquoted ([#7627](https://github.com/aquasecurity/trivy/issues/7627)) ([3e1fa21](https://github.com/aquasecurity/trivy/commit/3e1fa2100074e840bacdd65947425b08750b7d9a))


### Performance Improvements

* **misconf:** use port ranges instead of enumeration ([#7549](https://github.com/aquasecurity/trivy/issues/7549)) ([1f9fc13](https://github.com/aquasecurity/trivy/commit/1f9fc13da4a1e7c76c978e4f8e119bfd61a0480e))


### Reverts

* **java:** stop supporting of `test` scope for `pom.xml` files ([#7488](https://github.com/aquasecurity/trivy/issues/7488)) ([b0222fe](https://github.com/aquasecurity/trivy/commit/b0222feeb586ec59904bb321fda8f3f22496d07b))

## [0.55.0](https://github.com/aquasecurity/trivy/compare/v0.54.0...v0.55.0) (2024-09-03)


### ⚠ BREAKING CHANGES

* **cli:** delete deprecated SBOM flags ([#7266](https://github.com/aquasecurity/trivy/issues/7266))

### Features

* **cli:** delete deprecated SBOM flags ([#7266](https://github.com/aquasecurity/trivy/issues/7266)) ([7024572](https://github.com/aquasecurity/trivy/commit/70245721372720027b7089bd61c693df48add865))
* **go:** use `toolchain` as `stdlib` version for `go.mod` files ([#7163](https://github.com/aquasecurity/trivy/issues/7163)) ([2d80769](https://github.com/aquasecurity/trivy/commit/2d80769c34b118851640411fff9dac0b3e353e82))
* **java:** add `test` scope support for `pom.xml` files ([#7414](https://github.com/aquasecurity/trivy/issues/7414)) ([2d97700](https://github.com/aquasecurity/trivy/commit/2d97700d10665142d2f66d7910202bec82116209))
* **misconf:** Add support for using spec from on-disk bundle ([#7179](https://github.com/aquasecurity/trivy/issues/7179)) ([be86126](https://github.com/aquasecurity/trivy/commit/be861265cafc89787fda09c59b2ef175e3d04204))
* **misconf:** ignore duplicate checks ([#7317](https://github.com/aquasecurity/trivy/issues/7317)) ([9ef05fc](https://github.com/aquasecurity/trivy/commit/9ef05fc6b171a264516a025b0b0bcbbc8cff10bc))
* **misconf:** iterator argument support for dynamic blocks ([#7236](https://github.com/aquasecurity/trivy/issues/7236)) ([fe92072](https://github.com/aquasecurity/trivy/commit/fe9207255a4f7f984ec1447f8a9219ae60e560c4))
* **misconf:** port and protocol support for EC2 networks ([#7146](https://github.com/aquasecurity/trivy/issues/7146)) ([98e136e](https://github.com/aquasecurity/trivy/commit/98e136eb7baa2b66f4233d96875c1490144e1594))
* **misconf:** scanning support for YAML and JSON ([#7311](https://github.com/aquasecurity/trivy/issues/7311)) ([efdbd8f](https://github.com/aquasecurity/trivy/commit/efdbd8f19ab0ab0c3b48293d43e51c81b7b03b89))
* **misconf:** support for ignore by nested attributes ([#7205](https://github.com/aquasecurity/trivy/issues/7205)) ([44e4686](https://github.com/aquasecurity/trivy/commit/44e468603d44b077cc4606327fb3e7d7ca435e05))
* **misconf:** support for policy and bucket grants ([#7284](https://github.com/aquasecurity/trivy/issues/7284)) ([a817fae](https://github.com/aquasecurity/trivy/commit/a817fae85b7272b391b737ec86673a7cab722bae))
* **misconf:** variable support for Terraform Plan ([#7228](https://github.com/aquasecurity/trivy/issues/7228)) ([db2c955](https://github.com/aquasecurity/trivy/commit/db2c95598da098ca610825089eb4ab63b789b215))
* **python:** use minimum version for pip packages ([#7348](https://github.com/aquasecurity/trivy/issues/7348)) ([e9b43f8](https://github.com/aquasecurity/trivy/commit/e9b43f81e67789b067352fcb6aa55bc9478bc518))
* **report:** export modified findings in JSON ([#7383](https://github.com/aquasecurity/trivy/issues/7383)) ([7aea79d](https://github.com/aquasecurity/trivy/commit/7aea79dd93cfb61453766dbbb2e3fc0fbd317852))
* **sbom:** set User-Agent header on requests to Rekor ([#7396](https://github.com/aquasecurity/trivy/issues/7396)) ([af1d257](https://github.com/aquasecurity/trivy/commit/af1d257730422d238871beb674767f8f83c5d06a))
* **server:** add internal `--path-prefix` flag for client/server mode ([#7321](https://github.com/aquasecurity/trivy/issues/7321)) ([24a4563](https://github.com/aquasecurity/trivy/commit/24a45636867b893ff54c5ce07197f3b5c6db1d9b))
* **server:** Make Trivy Server Multiplexer Exported ([#7389](https://github.com/aquasecurity/trivy/issues/7389)) ([4c6e8ca](https://github.com/aquasecurity/trivy/commit/4c6e8ca9cc9591799907cc73075f2d740e303b8f))
* **vm:** Support direct filesystem ([#7058](https://github.com/aquasecurity/trivy/issues/7058)) ([45b3f34](https://github.com/aquasecurity/trivy/commit/45b3f344042bcd90ca63ab696b69bff0e9ab4e36))
* **vm:** support the Ext2/Ext3 filesystems ([#6983](https://github.com/aquasecurity/trivy/issues/6983)) ([35c60f0](https://github.com/aquasecurity/trivy/commit/35c60f030fa48de8d8e57958e5ba379814126831))
* **vuln:** Add `--detection-priority` flag for accuracy tuning ([#7288](https://github.com/aquasecurity/trivy/issues/7288)) ([fd8348d](https://github.com/aquasecurity/trivy/commit/fd8348d610f20c6c33da81cd7b0e7d5504ce26be))


### Bug Fixes

* **aws:** handle ECR repositories in different regions ([#6217](https://github.com/aquasecurity/trivy/issues/6217)) ([feaef96](https://github.com/aquasecurity/trivy/commit/feaef9699df5d8ca399770e701a59d7c0ff979a3))
* **flag:** incorrect behavior for deprected flag `--clear-cache` ([#7281](https://github.com/aquasecurity/trivy/issues/7281)) ([2a0e529](https://github.com/aquasecurity/trivy/commit/2a0e529c36057b572119815af59c28e4790034ca))
* **helm:** explicitly define `kind` and `apiVersion` of `volumeClaimTemplate` element ([#7362](https://github.com/aquasecurity/trivy/issues/7362)) ([da4ebfa](https://github.com/aquasecurity/trivy/commit/da4ebfa1a741f3f8b0b43289b4028afe763f7d43))
* **java:** Return error when trying to find a remote pom to avoid segfault ([#7275](https://github.com/aquasecurity/trivy/issues/7275)) ([49d5270](https://github.com/aquasecurity/trivy/commit/49d5270163e305f88fedcf50412973736e69dc69))
* **license:** add license handling to JUnit template ([#7409](https://github.com/aquasecurity/trivy/issues/7409)) ([f80183c](https://github.com/aquasecurity/trivy/commit/f80183c1139b21bb95bc64e216358f4a76001a65))
* logger initialization before flags parsing ([#7372](https://github.com/aquasecurity/trivy/issues/7372)) ([c929290](https://github.com/aquasecurity/trivy/commit/c929290c3c0e4e91337264d69e75ccb60522bc65))
* **misconf:** change default TLS values for the Azure storage account ([#7345](https://github.com/aquasecurity/trivy/issues/7345)) ([aadb090](https://github.com/aquasecurity/trivy/commit/aadb09078843250c66087f46db9a2aa48094a118))
* **misconf:** do not filter Terraform plan JSON by name ([#7406](https://github.com/aquasecurity/trivy/issues/7406)) ([9d7264a](https://github.com/aquasecurity/trivy/commit/9d7264af8e85bcc0dba600b8366d0470d455251c))
* **misconf:** do not recreate filesystem map ([#7416](https://github.com/aquasecurity/trivy/issues/7416)) ([3a5d091](https://github.com/aquasecurity/trivy/commit/3a5d091759564496992a83fb2015a21c84a22213))
* **misconf:** do not register Rego libs in checks registry ([#7420](https://github.com/aquasecurity/trivy/issues/7420)) ([a5aa63e](https://github.com/aquasecurity/trivy/commit/a5aa63eff7e229744090f9ad300c1bec3259397e))
* **misconf:** do not set default value for default_cache_behavior ([#7234](https://github.com/aquasecurity/trivy/issues/7234)) ([f0ed5e4](https://github.com/aquasecurity/trivy/commit/f0ed5e4ced7e60af35c88d5d084aa4b7237f4973))
* **misconf:** fix infer type for null value ([#7424](https://github.com/aquasecurity/trivy/issues/7424)) ([0cac3ac](https://github.com/aquasecurity/trivy/commit/0cac3ac7075017628a21a7990941df04cbc16dbe))
* **misconf:** init frameworks before updating them ([#7376](https://github.com/aquasecurity/trivy/issues/7376)) ([b65b32d](https://github.com/aquasecurity/trivy/commit/b65b32ddfa6fc62ac81ad9fa580e1f5a327864f5))
* **misconf:** load only submodule if it is specified in source ([#7112](https://github.com/aquasecurity/trivy/issues/7112)) ([a4180bd](https://github.com/aquasecurity/trivy/commit/a4180bddd43d86e479edf0afe0c362021d071482))
* **misconf:** support deprecating for Go checks ([#7377](https://github.com/aquasecurity/trivy/issues/7377)) ([2a6c7ab](https://github.com/aquasecurity/trivy/commit/2a6c7ab3b338ce4a8f99d6ac3508c2531dcbe812))
* **misconf:** use module to log when metadata retrieval fails ([#7405](https://github.com/aquasecurity/trivy/issues/7405)) ([0799770](https://github.com/aquasecurity/trivy/commit/0799770b8827a8276ad0d6d9ac7e0381c286757c))
* **misconf:** wrap Azure PortRange in iac types ([#7357](https://github.com/aquasecurity/trivy/issues/7357)) ([c5c62d5](https://github.com/aquasecurity/trivy/commit/c5c62d5ff05420321f9cdbfb93e2591e0866a342))
* **nodejs:** check all `importers` to detect dev deps from pnpm-lock.yaml file ([#7387](https://github.com/aquasecurity/trivy/issues/7387)) ([fd9ed3a](https://github.com/aquasecurity/trivy/commit/fd9ed3a330bc66e229bcbdc262dc296a3bf01f54))
* **plugin:** do not call GitHub content API for releases and tags ([#7274](https://github.com/aquasecurity/trivy/issues/7274)) ([b3ee6da](https://github.com/aquasecurity/trivy/commit/b3ee6dac269bd7847674f3ce985a5ff7f8f0ba38))
* **report:** escape `Message` field in `asff.tpl` template ([#7401](https://github.com/aquasecurity/trivy/issues/7401)) ([dd9733e](https://github.com/aquasecurity/trivy/commit/dd9733e950d3127aa2ac90c45ec7e2b88a2b47ca))
* safely check if the directory exists ([#7353](https://github.com/aquasecurity/trivy/issues/7353)) ([05a8297](https://github.com/aquasecurity/trivy/commit/05a829715f99cd90b122c64cd2f40157854e467b))
* **sbom:** use `NOASSERTION` for licenses fields in SPDX formats ([#7403](https://github.com/aquasecurity/trivy/issues/7403)) ([c96dcdd](https://github.com/aquasecurity/trivy/commit/c96dcdd440a14cdd1b01ac473b2c15e4698e387b))
* **secret:** use `.eyJ` keyword for JWT secret ([#7410](https://github.com/aquasecurity/trivy/issues/7410)) ([bf64003](https://github.com/aquasecurity/trivy/commit/bf64003ac8b209f34b88f228918a96d4f9dac5e0))
* **secret:** use only line with secret for long secret lines ([#7412](https://github.com/aquasecurity/trivy/issues/7412)) ([391448a](https://github.com/aquasecurity/trivy/commit/391448aba9fcb0a4138225e5ab305e4e6707c603))
* **terraform:** add aws_region name to presets ([#7184](https://github.com/aquasecurity/trivy/issues/7184)) ([bb2e26a](https://github.com/aquasecurity/trivy/commit/bb2e26a0ab707b718f6a890cbc87e2492298b6e5))


### Performance Improvements

* **misconf:** do not convert contents of a YAML file to string ([#7292](https://github.com/aquasecurity/trivy/issues/7292)) ([85dadf5](https://github.com/aquasecurity/trivy/commit/85dadf56265647c000191561db10b08a4948c140))
* **misconf:** optimize work with context ([#6968](https://github.com/aquasecurity/trivy/issues/6968)) ([2b6d8d9](https://github.com/aquasecurity/trivy/commit/2b6d8d9227fb6ecc9386a14333964c23c0370a52))
* **misconf:** use json.Valid to check validity of JSON ([#7308](https://github.com/aquasecurity/trivy/issues/7308)) ([c766831](https://github.com/aquasecurity/trivy/commit/c766831069e188226efafeec184e41498685ed85))

## [0.54.0](https://github.com/aquasecurity/trivy/compare/v0.53.0...v0.54.0) (2024-07-30)


### Features

* add `log.FilePath()` function for logger ([#7080](https://github.com/aquasecurity/trivy/issues/7080)) ([1f5f348](https://github.com/aquasecurity/trivy/commit/1f5f34895823fae81bf521fc939bee743a50e304))
* add openSUSE tumbleweed detection and scanning ([#6965](https://github.com/aquasecurity/trivy/issues/6965)) ([17b5dbf](https://github.com/aquasecurity/trivy/commit/17b5dbfa12180414b87859c6c46bfe6cc5ecf7ba))
* **cli:** rename `--vuln-type` flag to `--pkg-types` flag ([#7104](https://github.com/aquasecurity/trivy/issues/7104)) ([7cbdb0a](https://github.com/aquasecurity/trivy/commit/7cbdb0a0b5dff33e506e1c1f3119951fa241b432))
* **mariner:** Add support for Azure Linux ([#7186](https://github.com/aquasecurity/trivy/issues/7186)) ([5cbc452](https://github.com/aquasecurity/trivy/commit/5cbc452a09822d1bf300ead88f0d613d4cf0349a))
* **misconf:** enabled China configuration for ACRs ([#7156](https://github.com/aquasecurity/trivy/issues/7156)) ([d1ec89d](https://github.com/aquasecurity/trivy/commit/d1ec89d1db4b039f0e31076ccd1ca969fb15628e))
* **nodejs:** add license parser to pnpm analyser ([#7036](https://github.com/aquasecurity/trivy/issues/7036)) ([03ac93d](https://github.com/aquasecurity/trivy/commit/03ac93dc208f1b40896f3fa11fa1d45293176dca))
* **sbom:** add image labels into `SPDX` and `CycloneDX` reports ([#7257](https://github.com/aquasecurity/trivy/issues/7257)) ([4a2f492](https://github.com/aquasecurity/trivy/commit/4a2f492c6e685ff577fb96a7006cd0c43755baf4))
* **sbom:** add vulnerability support for SPDX formats ([#7213](https://github.com/aquasecurity/trivy/issues/7213)) ([efb1f69](https://github.com/aquasecurity/trivy/commit/efb1f6938321eec3529ef4fea6608261f6771ae0))
* share build-in rules ([#7207](https://github.com/aquasecurity/trivy/issues/7207)) ([bff317c](https://github.com/aquasecurity/trivy/commit/bff317c77bf4a5f615a80d9875d129213bd52f6d))
* **vex:** retrieve VEX attestations from OCI registries ([#7249](https://github.com/aquasecurity/trivy/issues/7249)) ([c2fd2e0](https://github.com/aquasecurity/trivy/commit/c2fd2e0d89567a0ccd996dda8790f3c3305ea6f7))
* **vex:** VEX Repository support ([#7206](https://github.com/aquasecurity/trivy/issues/7206)) ([88ba460](https://github.com/aquasecurity/trivy/commit/88ba46047c93e6046292523ae701de774dfdc4dc))
* **vuln:** add `--pkg-relationships` ([#7237](https://github.com/aquasecurity/trivy/issues/7237)) ([5c37361](https://github.com/aquasecurity/trivy/commit/5c37361600d922db27dd594b2a80c010a19b3a6e))


### Bug Fixes

* Add dependencyManagement exclusions to the child exclusions ([#6969](https://github.com/aquasecurity/trivy/issues/6969)) ([dc68a66](https://github.com/aquasecurity/trivy/commit/dc68a662a701980d6529f61a65006f1e4728a3e5))
* add missing platform and type to spec ([#7149](https://github.com/aquasecurity/trivy/issues/7149)) ([c8a7abd](https://github.com/aquasecurity/trivy/commit/c8a7abd3b508975fcf10c254d13d1a2cd42da657))
* **cli:** error on missing config file ([#7154](https://github.com/aquasecurity/trivy/issues/7154)) ([7fa5e7d](https://github.com/aquasecurity/trivy/commit/7fa5e7d0ab67f20d434b2922725988695e32e6af))
* close file when failed to open gzip ([#7164](https://github.com/aquasecurity/trivy/issues/7164)) ([2a577a7](https://github.com/aquasecurity/trivy/commit/2a577a7bae37e5731dceaea8740683573b6b70a5))
* **dotnet:** don't include non-runtime libraries into report for `*.deps.json` files ([#7039](https://github.com/aquasecurity/trivy/issues/7039)) ([5bc662b](https://github.com/aquasecurity/trivy/commit/5bc662be9a8f072599f90abfd3b400c8ab055ed6))
* **dotnet:** show `nuget package dir not found` log only when checking `nuget` packages ([#7194](https://github.com/aquasecurity/trivy/issues/7194)) ([d76feba](https://github.com/aquasecurity/trivy/commit/d76febaee107c645e864da0f4d74a8f6ae4ad232))
* ignore nodes when listing permission is not allowed ([#7107](https://github.com/aquasecurity/trivy/issues/7107)) ([25f8143](https://github.com/aquasecurity/trivy/commit/25f8143f120965c636c5ea8386398b211b082398))
* **java:** avoid panic if deps from `pom` in `it` dir are not found ([#7245](https://github.com/aquasecurity/trivy/issues/7245)) ([4e54a7e](https://github.com/aquasecurity/trivy/commit/4e54a7e84c33c1be80c52c6db78c634bc3911715))
* **java:** use `go-mvn-version` to remove `Package` duplicates ([#7088](https://github.com/aquasecurity/trivy/issues/7088)) ([a7a304d](https://github.com/aquasecurity/trivy/commit/a7a304d53e1ce230f881c28c4f35885774cf3b9a))
* **misconf:** do not evaluate TF when a load error occurs ([#7109](https://github.com/aquasecurity/trivy/issues/7109)) ([f27c236](https://github.com/aquasecurity/trivy/commit/f27c236d6e155cb366aeef619b6ea96d20fb93da))
* **nodejs:** detect direct dependencies when using `latest` version for files `yarn.lock` + `package.json` ([#7110](https://github.com/aquasecurity/trivy/issues/7110)) ([54bb8bd](https://github.com/aquasecurity/trivy/commit/54bb8bdfb934d114b5570005853bf4bc0d40c609))
* **report:** hide empty table when all secrets/license/misconfigs are ignored ([#7171](https://github.com/aquasecurity/trivy/issues/7171)) ([c3036de](https://github.com/aquasecurity/trivy/commit/c3036de6d7719323d306a9666ccc8d928d936f9a))
* **secret:** skip regular strings contain secret patterns ([#7182](https://github.com/aquasecurity/trivy/issues/7182)) ([174b1e3](https://github.com/aquasecurity/trivy/commit/174b1e3515a6394cf8d523216d6267c1aefb820a))
* **secret:** trim excessively long lines ([#7192](https://github.com/aquasecurity/trivy/issues/7192)) ([92b13be](https://github.com/aquasecurity/trivy/commit/92b13be668bd20f8e9dac2f0cb8e5a2708b9b3b5))
* **secret:** update length of `hugging-face-access-token` ([#7216](https://github.com/aquasecurity/trivy/issues/7216)) ([8c87194](https://github.com/aquasecurity/trivy/commit/8c87194f0a6b194bc5d340c8a65bd99a3132d973))
* **server:** pass license categories to options ([#7203](https://github.com/aquasecurity/trivy/issues/7203)) ([9d52018](https://github.com/aquasecurity/trivy/commit/9d5201808da89607ae43570bdf1f335b482a6b79))


### Performance Improvements

* **debian:** use `bytes.Index` in `emptyLineSplit` to cut allocation ([#7065](https://github.com/aquasecurity/trivy/issues/7065)) ([acbec05](https://github.com/aquasecurity/trivy/commit/acbec053c985388a26d899e73b4b7f5a6d1fa210))

## [0.53.0](https://github.com/aquasecurity/trivy/compare/v0.52.0...v0.53.0) (2024-07-01)


### ⚠ BREAKING CHANGES

* **k8s:** node-collector dynamic commands support ([#6861](https://github.com/aquasecurity/trivy/issues/6861))
* add clean subcommand ([#6993](https://github.com/aquasecurity/trivy/issues/6993))
* **aws:** Remove aws subcommand ([#6995](https://github.com/aquasecurity/trivy/issues/6995))

### Features

* add clean subcommand ([#6993](https://github.com/aquasecurity/trivy/issues/6993)) ([8d0ae1f](https://github.com/aquasecurity/trivy/commit/8d0ae1f5de72d92a043dcd6b7c164d30e51b6047))
* Add local ImageID to SARIF metadata ([#6522](https://github.com/aquasecurity/trivy/issues/6522)) ([f144e91](https://github.com/aquasecurity/trivy/commit/f144e912d34234f00b5a13b7a11a0019fa978b27))
* add memory cache backend ([#7048](https://github.com/aquasecurity/trivy/issues/7048)) ([55ccd06](https://github.com/aquasecurity/trivy/commit/55ccd06df43f6ff28685f46d215ccb70f55916d2))
* **aws:** Remove aws subcommand ([#6995](https://github.com/aquasecurity/trivy/issues/6995)) ([979e118](https://github.com/aquasecurity/trivy/commit/979e118a9e0ca8943bef9143f492d7eb1fd4d863))
* **conda:** add licenses support for `environment.yml` files ([#6953](https://github.com/aquasecurity/trivy/issues/6953)) ([654217a](https://github.com/aquasecurity/trivy/commit/654217a65485ca0a07771ea61071977894eb4920))
* **dart:** use first version of constraint for dependencies using SDK version ([#6239](https://github.com/aquasecurity/trivy/issues/6239)) ([042d6b0](https://github.com/aquasecurity/trivy/commit/042d6b08c283105c258a3dda98983b345a5305c3))
* **image:** Set User-Agent header for Trivy container registry requests ([#6868](https://github.com/aquasecurity/trivy/issues/6868)) ([9b31697](https://github.com/aquasecurity/trivy/commit/9b31697274c8743d6e5a8f7a1a05daf60cd15910))
* **java:** add support for `maven-metadata.xml` files for remote snapshot repositories. ([#6950](https://github.com/aquasecurity/trivy/issues/6950)) ([1f8fca1](https://github.com/aquasecurity/trivy/commit/1f8fca1fc77b989bb4e3ba820b297464dbdd825f))
* **java:** add support for sbt projects using sbt-dependency-lock ([#6882](https://github.com/aquasecurity/trivy/issues/6882)) ([f18d035](https://github.com/aquasecurity/trivy/commit/f18d035ae13b281c96aa4ed69ca32e507d336e66))
* **k8s:** node-collector dynamic commands support ([#6861](https://github.com/aquasecurity/trivy/issues/6861)) ([8d618e4](https://github.com/aquasecurity/trivy/commit/8d618e48a2f1b60c2e4c49cdd9deb8eb45c972b0))
* **misconf:** add metadata to Cloud schema ([#6831](https://github.com/aquasecurity/trivy/issues/6831)) ([02d5404](https://github.com/aquasecurity/trivy/commit/02d540478d495416b50d7e8b187ff9f5bba41f45))
* **misconf:** add support for AWS::EC2::SecurityGroupIngress/Egress ([#6755](https://github.com/aquasecurity/trivy/issues/6755)) ([55fa610](https://github.com/aquasecurity/trivy/commit/55fa6109cd0463fd3221aae41ca7b1d8c44ad430))
* **misconf:** API Gateway V1 support for CloudFormation ([#6874](https://github.com/aquasecurity/trivy/issues/6874)) ([8491469](https://github.com/aquasecurity/trivy/commit/8491469f0b35bd9df706a433669f5b62239d4ef3))
* **misconf:** support of selectors for all providers for Rego ([#6905](https://github.com/aquasecurity/trivy/issues/6905)) ([bc3741a](https://github.com/aquasecurity/trivy/commit/bc3741ae2c68cdd00fc0aef7e51985568b2eb78a))
* **php:** add installed.json file support ([#4865](https://github.com/aquasecurity/trivy/issues/4865)) ([edc556b](https://github.com/aquasecurity/trivy/commit/edc556b85e3554c31e19b1ece189effb9ba2be12))
* **plugin:** add support for nested archives ([#6845](https://github.com/aquasecurity/trivy/issues/6845)) ([622c67b](https://github.com/aquasecurity/trivy/commit/622c67b7647f94d0a0ca3acf711d8f847cdd8d98))
* **sbom:** migrate to `CycloneDX v1.6` ([#6903](https://github.com/aquasecurity/trivy/issues/6903)) ([09e50ce](https://github.com/aquasecurity/trivy/commit/09e50ce6a82073ba62f1732d5aa0cd2701578693))


### Bug Fixes

* **c:** don't skip conan files from `file-patterns` and scan `.conan2` cache dir ([#6949](https://github.com/aquasecurity/trivy/issues/6949)) ([38b35dd](https://github.com/aquasecurity/trivy/commit/38b35dd3c804027e7a6e6a9d3c87b7ac333896c5))
* **cli:** show info message only when --scanners is available ([#7032](https://github.com/aquasecurity/trivy/issues/7032)) ([e9fc3e3](https://github.com/aquasecurity/trivy/commit/e9fc3e3397564512038ddeca2adce0efcb3f93c5))
* **cyclonedx:** trim non-URL info for `advisory.url` ([#6952](https://github.com/aquasecurity/trivy/issues/6952)) ([417212e](https://github.com/aquasecurity/trivy/commit/417212e0930aa52a27ebdc1b9370d2943ce0f8fa))
* **debian:** take installed files from the origin layer ([#6849](https://github.com/aquasecurity/trivy/issues/6849)) ([089b953](https://github.com/aquasecurity/trivy/commit/089b953462260f01c40bdf588b2568ae0ef658bc))
* **image:** parse `image.inspect.Created` field only for non-empty values ([#6948](https://github.com/aquasecurity/trivy/issues/6948)) ([0af5730](https://github.com/aquasecurity/trivy/commit/0af5730cbe56686417389c2fad643c1bdbb33999))
* **license:** return license separation using separators  `,`, `or`, etc. ([#6916](https://github.com/aquasecurity/trivy/issues/6916)) ([52f7aa5](https://github.com/aquasecurity/trivy/commit/52f7aa54b520a90a19736703f8ea63cc20fab104))
* **misconf:** fix caching of modules in subdirectories ([#6814](https://github.com/aquasecurity/trivy/issues/6814)) ([0bcfedb](https://github.com/aquasecurity/trivy/commit/0bcfedbcaa9bbe30ee5ecade5b98e9ce3cc54c9b))
* **misconf:** fix parsing of engine links and frameworks ([#6937](https://github.com/aquasecurity/trivy/issues/6937)) ([ec68c9a](https://github.com/aquasecurity/trivy/commit/ec68c9ab4580d057720179173d58734402c92af4))
* **misconf:** handle source prefix to ignore ([#6945](https://github.com/aquasecurity/trivy/issues/6945)) ([c3192f0](https://github.com/aquasecurity/trivy/commit/c3192f061d7e84eaf38df8df7c879dc00b4ca137))
* **misconf:** parsing numbers without fraction as int ([#6834](https://github.com/aquasecurity/trivy/issues/6834)) ([8141a13](https://github.com/aquasecurity/trivy/commit/8141a137ba50b553a9da877d95c7ccb491d041c6))
* **nodejs:** fix infinite loop when package link from `package-lock.json` file is broken ([#6858](https://github.com/aquasecurity/trivy/issues/6858)) ([cf5aa33](https://github.com/aquasecurity/trivy/commit/cf5aa336e660e4c98481ebf8d15dd4e54c38581e))
* **nodejs:** fix infinity loops for `pnpm` with cyclic imports ([#6857](https://github.com/aquasecurity/trivy/issues/6857)) ([7d083bc](https://github.com/aquasecurity/trivy/commit/7d083bc890eccc3bf32765c6d7e922cab2e2ef94))
* **plugin:** respect `--insecure` ([#7022](https://github.com/aquasecurity/trivy/issues/7022)) ([3d02a31](https://github.com/aquasecurity/trivy/commit/3d02a31b44924f9e2495aae087f7ca9de3314db4))
* **purl:** add missed os types ([#6955](https://github.com/aquasecurity/trivy/issues/6955)) ([2d85a00](https://github.com/aquasecurity/trivy/commit/2d85a003b22298d1101f84559f7c6b470f2b3909))
* **python:** compare pkg names from `poetry.lock` and `pyproject.toml` in lowercase ([#6852](https://github.com/aquasecurity/trivy/issues/6852)) ([faa9d92](https://github.com/aquasecurity/trivy/commit/faa9d92cfeb8d924deda2dac583b6c97099c08d9))
* **sbom:** don't overwrite `srcEpoch` when decoding SBOM files ([#6866](https://github.com/aquasecurity/trivy/issues/6866)) ([04af59c](https://github.com/aquasecurity/trivy/commit/04af59c2906bcfc7f7970b4e8f45a90f04313170))
* **sbom:** fix panic when scanning SBOM file without root component into SBOM format ([#7051](https://github.com/aquasecurity/trivy/issues/7051)) ([3d4ae8b](https://github.com/aquasecurity/trivy/commit/3d4ae8b5be94cd9b00badeece8d86c2258b2cd90))
* **sbom:** take pkg name from `purl` for maven pkgs ([#7008](https://github.com/aquasecurity/trivy/issues/7008)) ([a76e328](https://github.com/aquasecurity/trivy/commit/a76e3286c413de3dec55394fb41dd627dfee37ae))
* **sbom:** use `purl` for `bitnami` pkg names ([#6982](https://github.com/aquasecurity/trivy/issues/6982)) ([7eabb92](https://github.com/aquasecurity/trivy/commit/7eabb92ec2e617300433445718be07ac74956454))
* **sbom:** use package UIDs for uniqueness ([#7042](https://github.com/aquasecurity/trivy/issues/7042)) ([14d71ba](https://github.com/aquasecurity/trivy/commit/14d71ba63c39e51dd4179ba2d6002b46e1816e90))
* **secret:** `Asymmetric Private Key` shouldn't start with space ([#6867](https://github.com/aquasecurity/trivy/issues/6867)) ([bb26445](https://github.com/aquasecurity/trivy/commit/bb26445e3df198df77930329f532ac5ab7a67af2))
* **suse:** Add SLES 15.6 and Leap 15.6 ([#6964](https://github.com/aquasecurity/trivy/issues/6964)) ([5ee4e9d](https://github.com/aquasecurity/trivy/commit/5ee4e9d30ea814f60fd5705361cabf2e83a47a78))
* use embedded when command path not found ([#7037](https://github.com/aquasecurity/trivy/issues/7037)) ([137c916](https://github.com/aquasecurity/trivy/commit/137c9164238ffd989a0c5ed24f23a55bbf341f6e))

## [0.52.0](https://github.com/aquasecurity/trivy/compare/v0.51.1...v0.52.0) (2024-06-03)


### Features

* Add Julia language analyzer support ([#5635](https://github.com/aquasecurity/trivy/issues/5635)) ([fecafb1](https://github.com/aquasecurity/trivy/commit/fecafb1fc5bb129c7485342a0775f0dd8bedd28e))
* add support for plugin index ([#6674](https://github.com/aquasecurity/trivy/issues/6674)) ([26faf8f](https://github.com/aquasecurity/trivy/commit/26faf8f3f04b1c5f9f81c03ffc6b2008732207e2))
* **misconf:** Add support for deprecating a check ([#6664](https://github.com/aquasecurity/trivy/issues/6664)) ([88702cf](https://github.com/aquasecurity/trivy/commit/88702cfd5918b093defc5b5580f7cbf16f5f2417))
* **misconf:** add Terraform 'removed' block to schema ([#6640](https://github.com/aquasecurity/trivy/issues/6640)) ([b7a0a13](https://github.com/aquasecurity/trivy/commit/b7a0a131a03ed49c08d3b0d481bc9284934fd6e1))
* **misconf:** register builtin Rego funcs from trivy-checks ([#6616](https://github.com/aquasecurity/trivy/issues/6616)) ([7c22ee3](https://github.com/aquasecurity/trivy/commit/7c22ee3df5ee51beb90e44428a99541b3d19ab98))
* **misconf:** resolve tf module from OpenTofu compatible registry ([#6743](https://github.com/aquasecurity/trivy/issues/6743)) ([ac74520](https://github.com/aquasecurity/trivy/commit/ac7452009bf7ca0fa8ee1de8807c792eabad405a))
* **misconf:** support for VPC resources for inbound/outbound rules ([#6779](https://github.com/aquasecurity/trivy/issues/6779)) ([349caf9](https://github.com/aquasecurity/trivy/commit/349caf96bc3dd81551d488044f1adfdb947f39fb))
* **misconf:** support symlinks inside of Helm archives ([#6621](https://github.com/aquasecurity/trivy/issues/6621)) ([4eae37c](https://github.com/aquasecurity/trivy/commit/4eae37c52b035b3576361c12f70d3d9517d0a73c))
* **nodejs:** add v9 pnpm lock file support ([#6617](https://github.com/aquasecurity/trivy/issues/6617)) ([1e08648](https://github.com/aquasecurity/trivy/commit/1e0864842e32a709941d4b4e8f521602bcee684d))
* **plugin:** specify plugin version ([#6683](https://github.com/aquasecurity/trivy/issues/6683)) ([d6dc567](https://github.com/aquasecurity/trivy/commit/d6dc56732babbc9d7f788c280a768d8648aa093d))
* **python:** add license support for `requirement.txt` files ([#6782](https://github.com/aquasecurity/trivy/issues/6782)) ([29615be](https://github.com/aquasecurity/trivy/commit/29615be85e8bfeaf5a0cd51829b1898c55fa4274))
* **python:** add line number support for `requirement.txt` files ([#6729](https://github.com/aquasecurity/trivy/issues/6729)) ([2bc54ad](https://github.com/aquasecurity/trivy/commit/2bc54ad2752aba5de4380cb92c13b09c0abefd73))
* **report:** Include licenses and secrets filtered by rego to ModifiedFindings ([#6483](https://github.com/aquasecurity/trivy/issues/6483)) ([fa3cf99](https://github.com/aquasecurity/trivy/commit/fa3cf993eace4be793f85907b42365269c597b91))
* **vex:** improve relationship support in CSAF VEX ([#6735](https://github.com/aquasecurity/trivy/issues/6735)) ([a447f6b](https://github.com/aquasecurity/trivy/commit/a447f6ba94b6f8b14177dc5e4369a788e2020d90))
* **vex:** support non-root components for products in OpenVEX ([#6728](https://github.com/aquasecurity/trivy/issues/6728)) ([9515695](https://github.com/aquasecurity/trivy/commit/9515695d45e9b5c20890e27e21e3ab45bfd4ce5f))


### Bug Fixes

* clean up golangci lint configuration ([#6797](https://github.com/aquasecurity/trivy/issues/6797)) ([62de6f3](https://github.com/aquasecurity/trivy/commit/62de6f3feba6e4c56ad3922441d5b0f150c3d6b7))
* **cli:** always output fatal errors to stderr ([#6827](https://github.com/aquasecurity/trivy/issues/6827)) ([c2b9132](https://github.com/aquasecurity/trivy/commit/c2b9132a7e933a68df4cc0eb86aab23719ded1b5))
* close APKINDEX archive file ([#6672](https://github.com/aquasecurity/trivy/issues/6672)) ([5caf437](https://github.com/aquasecurity/trivy/commit/5caf4377f3a7fcb1f6e1a84c67136ae62d100be3))
* close settings.xml ([#6768](https://github.com/aquasecurity/trivy/issues/6768)) ([9c3e895](https://github.com/aquasecurity/trivy/commit/9c3e895fcb0852c00ac03ed21338768f76b5273b))
* close testfile ([#6830](https://github.com/aquasecurity/trivy/issues/6830)) ([aa0c413](https://github.com/aquasecurity/trivy/commit/aa0c413814e8915b38d2285c6a8ba5bc3f0705b4))
* **conda:** add support `pip` deps for `environment.yml` files ([#6675](https://github.com/aquasecurity/trivy/issues/6675)) ([150a773](https://github.com/aquasecurity/trivy/commit/150a77313e980cd63797a89a03afcbc97b285f38))
* **go:** add only non-empty root modules for `gobinaries` ([#6710](https://github.com/aquasecurity/trivy/issues/6710)) ([c96f2a5](https://github.com/aquasecurity/trivy/commit/c96f2a5b3de820da37e14594dd537c3b0949ae9c))
* **go:** include only `.version`|`.ver` (no prefixes) ldflags for `gobinaries` ([#6705](https://github.com/aquasecurity/trivy/issues/6705)) ([afb4f9d](https://github.com/aquasecurity/trivy/commit/afb4f9dc4730671ba004e1734fa66422c4c86dad))
* Golang version parsing from binaries w/GOEXPERIMENT ([#6696](https://github.com/aquasecurity/trivy/issues/6696)) ([696f2ae](https://github.com/aquasecurity/trivy/commit/696f2ae0ecdd4f90303f41249924a09ace70dd78))
* include packages unless it is not needed ([#6765](https://github.com/aquasecurity/trivy/issues/6765)) ([56dbe1f](https://github.com/aquasecurity/trivy/commit/56dbe1f6768fe67fbc1153b74fde0f83eaa1b281))
* **misconf:** don't shift ignore rule related to code ([#6708](https://github.com/aquasecurity/trivy/issues/6708)) ([39a746c](https://github.com/aquasecurity/trivy/commit/39a746c77837f873e87b81be40676818030f44c5))
* **misconf:** skip Rego errors with a nil location ([#6638](https://github.com/aquasecurity/trivy/issues/6638)) ([a2c522d](https://github.com/aquasecurity/trivy/commit/a2c522ddb229f049999c4ce74ef75a0e0f9fdc62))
* **misconf:** skip Rego errors with a nil location ([#6666](https://github.com/aquasecurity/trivy/issues/6666)) ([a126e10](https://github.com/aquasecurity/trivy/commit/a126e1075a44ef0e40c0dc1e214d1c5955f80242))
* node-collector high and critical cves ([#6707](https://github.com/aquasecurity/trivy/issues/6707)) ([ff32deb](https://github.com/aquasecurity/trivy/commit/ff32deb7bf9163c06963f557228260b3b8c161ed))
* **plugin:** initialize logger ([#6836](https://github.com/aquasecurity/trivy/issues/6836)) ([728e77a](https://github.com/aquasecurity/trivy/commit/728e77a7261dc3fcda1e61e79be066c789bbba0c))
* **python:** add package name and version validation for `requirements.txt` files. ([#6804](https://github.com/aquasecurity/trivy/issues/6804)) ([ea3a124](https://github.com/aquasecurity/trivy/commit/ea3a124fc7162c30c7f1a59bdb28db0b3c8bb86d))
* **report:** hide empty tables if all vulns has been filtered ([#6352](https://github.com/aquasecurity/trivy/issues/6352)) ([3d388d8](https://github.com/aquasecurity/trivy/commit/3d388d8552ef42d4d54176309a38c1879008527b))
* **sbom:** fix panic for `convert` mode when scanning json file derived from sbom file ([#6808](https://github.com/aquasecurity/trivy/issues/6808)) ([f92ea09](https://github.com/aquasecurity/trivy/commit/f92ea096856c7c262b05bd4d31c62689ebafac82))
* use of specified context to obtain cluster name ([#6645](https://github.com/aquasecurity/trivy/issues/6645)) ([39ebed4](https://github.com/aquasecurity/trivy/commit/39ebed45f8c218509d264bd3f3ca548fc33d2b3a))


### Performance Improvements

* **misconf:** parse rego input once ([#6615](https://github.com/aquasecurity/trivy/issues/6615)) ([67c6b1d](https://github.com/aquasecurity/trivy/commit/67c6b1d473999003d682bdb42657bbf3a4a69a9c))
