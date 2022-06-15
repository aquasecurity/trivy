# Policy

## Pass custom policies
You can pass directories including your custom policies through `--policy` option.
This can be repeated for specifying multiple directories.

```bash
cd examplex/misconf/
trivy conf --policy custom-policy/policy --policy combine/policy --namespaces user misconf/mixed
```

For more details, see [Custom Policies](../custom/index.md).

!!! tip
    You also need to specify `--namespaces` option.

## Pass custom data
You can pass directories including your custom data through `--data` option.
This can be repeated for specifying multiple directories.

```bash
cd examples/misconf/custom-data
trivy conf --policy ./policy --data ./data --namespaces user ./configs
```

For more details, see [Custom Data](../custom/data.md).

## Pass namespaces
By default, Trivy evaluates policies defined in `builtin.*`.
If you want to evaluate custom policies in other packages, you have to specify package prefixes through `--namespaces` option.
This can be repeated for specifying multiple packages.

``` bash
trivy conf --policy ./policy --namespaces main --namespaces user ./configs
```
