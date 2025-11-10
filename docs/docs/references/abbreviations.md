# Abbreviation List

This list compiles words that frequently appear in CLI flags or configuration files and are commonly abbreviated in industry and OSS communities.
Trivy may use the abbreviation in place of the full spelling for flag names.
It is also acceptable to add even shorter aliases if needed.

Words not included in this list should be spelled out in full when used in flags.

This list is intentionally limited to the most common and widely recognized abbreviations.
Excessive use of abbreviations in CLI flags can hinder initial user understanding and create a steeper learning curve.

!!! note
    This list serves as a guideline rather than a strict requirement.
    Its purpose is to maintain consistency across the project when naming flags and configuration options.
    While we strive to follow these abbreviations, there may be exceptions where context or clarity demands a different approach.

## Scope
This list focuses on abbreviations of single words commonly used in technical contexts. It does not include:

1. Acronyms formed from the initial letters of multiple words (e.g., OS for Operating System, HTTP for Hypertext Transfer Protocol)
2. Domain-specific terminology that already has standardized short forms
3. Brand names or product-specific abbreviations

The abbreviations listed here are primarily intended for CLI flags, configuration keys, and similar technical interfaces where brevity is valued while maintaining clarity.

## Example
For a flag containing multiple words, only abbreviate words that appear in this list.
For instance, in `--database-repository`, "database" is in the list so it should be abbreviated to "db", but "repository" is not in the list so it must be spelled out completely.
The correct flag name would be `--db-repository`.
It's acceptable to add a shorter alias like `--db-repo` if desired.

## List

| Full Name         | Default Abbreviation | Examples                                                  |
|-------------------|----------------------|-----------------------------------------------------------|
| application       | app                  | `--app-name`, `--app-mode`                                |
| authentication    | auth                 | `--auth-method`, `--auth-token`                           |
| authorization     | authz                | `--authz-rule`, `--authz-policy`                          |
| command           | cmd                  | `--cmd-option`, `--cmd-args`                              |
| configuration     | config               | `--config`, `--config-dir`                                |
| database          | db                   | `--db-repository`, `--db-user`, `--db-pass`               |
| development       | dev                  | `--dev-dependencies`, `--dev-mode`                        |
| directory         | dir                  | `--dir-path`, `--output-dir`                              |
| environment       | env                  | `--env-file`, `--env-vars`                                |
| information       | info                 | `--info-level`, `--show-info`                             |
| initialization    | init                 | `--init-script`, `--init-config`                          |
| library           | lib                  | `--lib-path`, `--lib-dir`                                 |
| maximum           | max                  | `--max-image-size`, `--max-depth`                         |
| minimum           | min                  | `--min-value`, `--min-severity`                           |
| misconfiguration  | misconfig            | `--misconfig-scanners`                                    |
| package           | pkg                  | `--pkg-types`                                             |
| production        | prod                 | `--prod-env`, `--prod-deploy`                             |
| specification     | spec                 | `--spec-file`, `--spec-version`                           |
| temporary         | tmp                  | `--tmp-dir`, `--tmp-file`                                 |
| utility           | util                 | `--util-script`, `--util-name`                            |
| vulnerability     | vuln                 | `--vuln-scan`, `--vuln-report`                            |