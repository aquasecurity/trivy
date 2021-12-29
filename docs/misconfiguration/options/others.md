# Others

!!! hint
    See also [Others](../../vulnerability/examples/others.md) in Vulnerability section.

## File patterns
When a directory is given as an input, Trivy will recursively look for and test all files based on file patterns.
The default file patterns are [here](../custom/index.md).

In addition to the default file patterns, the `--file-patterns` option takes regexp patterns to look for your files.
For example, it may be useful when your file name of Dockerfile doesn't match the default patterns.

This can be repeated for specifying multiple file patterns.
Allowed values are here:

- dockerfile
- yaml
- json
- toml
- hcl

For more details, see [an example](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/file-patterns)