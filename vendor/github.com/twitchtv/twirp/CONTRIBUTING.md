# Contributing

Thanks for helping make Twirp better! This is great!

## Twirp Design Principles

Contributions to Twirp should align with the project’s design principles:

 * Maintain backwards compatibility. Twirp has been in production at Twitch since 2016 and released to the public in January 2018. It is currently used by many companies and individuals with a variety of needs. There must be a compelling use-case and solid reasoning behind a major version upgrade.
 * Simple wire protocol and minimal public API. Fewer things in the core means fewer things to break. In addition, it ensures lower friction updates and easier to maintain implementations in other languages.
 * Avoid surprising behavior. For instance, mechanisms that can alter a program’s control flow in a surprising way (such as middleware or observability hooks) should be treated with caution.
 * Prefer pragmatism over bleeding-edge. Users should be able to deploy and accept updates to Twirp even if they are conservative on updating its dependencies. This includes Go, the protobuf compiler and runtime libraries, and the HTTP protocol.
 * Keep configuration to a minimum. For example: avoid adding flags to code generation commands, so that generated code is predictable across versions and platforms.
 * Limit dependencies where possible, so that they are easier to integrate and upgrade.
 * Prefer generated code over shared libraries between services and clients, so that it is easier to implement changes without forcing a lock-step upgrade across the ecosystem.

Examples of contributions that should be addressed with high priority:

 * Security updates.
 * Performance improvements.
 * Supporting new versions of key dependencies such as Go and Protobuf.
 * Documentation.
 * Making Twirp easier to integrate with other tools.

## Report an Issue

If you have run into a bug or want to discuss a new feature, please [file an issue](https://github.com/twitchtv/twirp/issues). If you'd rather not publicly discuss the issue, please email security@twitch.tv.

## Contributing Code with Pull Requests

Twirp uses github pull requests. Fork, hack away at your changes and submit. Most pull requests will go through a few iterations before they get merged. Different contributors will sometimes have different opinions, and often patches will need to be revised before they can get merged.

### Requirements

 * Add tests that cover your contribution. Overall code coverage should not decrease.
 * Twirp officially supports the last 3 releases of Go.
 * Protobuf version 3.x.x to generate code with the protoc command.
 * For linters and other tools, we use [retool](https://github.com/twitchtv/retool). If `make setup` is not able to install it, you can install it in your path with `go get github.com/twitchtv/retool` and then install tools with `retool build`.

### Running tests

Generally you want to make changes and run `make`, which will install all
dependencies we know about, build the core, and run tests. A few notes:

 * Clone the repo on `$GOPATH/src/github.com/twitchtv/twirp` (go modules not supported yet).
 * Run Go unit tests with `make test`.
 * Most tests of the Go server are in `internal/twirptest/service_test.go`.
 * Integration tests running the full stack in Go are in the [clientcompat](./clientcompat) directory.

## Contributing Documentation

Twirp's docs are generated with [Docusaurus](https://docusaurus.io/). You can
safely edit anything inside the [docs](./docs) directory, adding new pages or
editing them. You can edit the sidebar by editing
[website/sidebars.json](./website/sidebars.json).

Then, to render your changes, run docusaurus's local server. To do this:

 1. [Install docusaurus on your machine](https://docusaurus.io/docs/en/installation.html).
 2. `cd website`
 3. `npm start`
 4. Navigate to http://localhost:3000/twirp.

Follow [this guide](https://docusaurus.io/docs/en/tutorial-publish-site) to publish changes to the `gh-pages` branch.

## Making a New Release

Releasing versions is the responsibility of the core maintainers. Most people
can skip this section.

Twirp uses Github releases. To make a new release:

 1. Merge all changes that should be included in the release into the master branch.
 2. Update the version constant in `internal/gen/version.go`. Please respect [semantic versioning](http://semver.org/): `v<major>.<minor>.<patch>`.
 3. Run `make test_all` to re-generate code and run tests. Check that generated test files include the new version in the header comment.
 4. Add a new commit to master with a message like "Version vX.X.X release" and push.
 5. Tag the commit you just made: `git tag vX.X.X` and `git push origin --tags`.
 6. Go to Github https://github.com/twitchtv/twirp/releases and "Draft a new release".
 7. Make sure that all new functionality is properly documented, on code comments, PR description, and include links and/or upgrade instructions on the release. For example the [v7 release](https://github.com/twitchtv/twirp/releases/tag/v7.0.0). Minor releases can just include a link to the PR/PRs that were merged included into the release.


## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.

## Licensing

See the [LICENSE](https://github.com/twitchtv/twirp/blob/master/LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement) for larger changes.

