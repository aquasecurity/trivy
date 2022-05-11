# glob-intersection
Go package to check if the set of non-empty strings matched by the intersection of two regexp-style globs is non-empty.

### Examples
- `gintersect.NonEmpty("a.a.", ".b.b")` is `true` because both globs match the string `abab`.
- `gintersect.NonEmpty("[a-z]+", "[0-9]*)` is `false` because there are no non-empty strings that both globs match.

### Limitations

- It is assumed that all input is rooted at the beginning and the end, i.e, starts and ends with the regexp symbols `^` and `$` respectively. This is done because any non-rooted expressions will always match a non-empty set of non-empty strings.
- The only special symbols are:
  - `.` for any character.
  - `+` for 1 or more of the preceding expression.
  - `*` for 0 or more of the preceding expression.
  - `[` and `]` to define regexp-style character classes.
  - `-` to specify Unicode ranges inside character class definitions.
  - `\` escapes any special symbol, including itself.

### Complexity

Complexity is exponential in the number of flags (`+` or `*`) present in the glob with the smaller flag count.
Benchmarks (see [`non_empty_bench_test.go`](/non_empty_bench_test.go)) reveal that inputs where one of the globs has <= 10 flags, and both globs have 100s of characters, will run in less than a nanosecond. This should be ok for most use cases.

### Acknowledgements

[This StackOverflow discussion](https://stackoverflow.com/questions/18695727/algorithm-to-find-out-whether-the-matches-for-two-glob-patterns-or-regular-expr) for fleshing out the logic.
