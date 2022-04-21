# Debugging policies
When working on more complex queries (or when learning Rego), it's useful to see exactly how the policy is applied.
For this purpose you can use the `--trace` flag.
This will output a large trace from Open Policy Agent like the following:

!!! tip
    Only failed policies show traces. If you want to debug a passed policy, you need to make it fail on purpose.

```bash
$ trivy conf --trace configs/
2021-07-11T16:45:58.493+0300    INFO    Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 22, FAILURES: 1, EXCEPTIONS: 0)
Failures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+---------------------------+------------+----------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |        CHECK         | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------+----------+------------------------------------------+
| Dockerfile Security Check |   DS002    | Image user is 'root' |   HIGH   | Last USER command in                     |
|                           |            |                      |          | Dockerfile should not be 'root'          |
|                           |            |                      |          | -->avd.aquasec.com/appshield/ds002       |
+---------------------------+------------+----------------------+----------+------------------------------------------+

ID: DS002
File: Dockerfile
Namespace: appshield.dockerfile.DS002
Query: data.appshield.dockerfile.DS002.deny
Message: Last USER command in Dockerfile should not be 'root'
TRACE  Enter data.appshield.dockerfile.DS002.deny = _
TRACE  | Eval data.appshield.dockerfile.DS002.deny = _
TRACE  | Index data.appshield.dockerfile.DS002.deny matched 2 rules)
TRACE  | Enter data.appshield.dockerfile.DS002.deny
TRACE  | | Eval data.appshield.dockerfile.DS002.fail_user_count
TRACE  | | Index data.appshield.dockerfile.DS002.fail_user_count (matched 1 rule)
TRACE  | | Enter data.appshield.dockerfile.DS002.fail_user_count
TRACE  | | | Eval __local559__ = data.appshield.dockerfile.DS002.get_user
TRACE  | | | Index data.appshield.dockerfile.DS002.get_user (matched 1 rule)
TRACE  | | | Enter data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Eval user = data.lib.docker.user[_]
TRACE  | | | | Index data.lib.docker.user (matched 1 rule)
TRACE  | | | | Enter data.lib.docker.user
TRACE  | | | | | Eval instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | Eval count(__local559__, __local391__)
TRACE  | | | Eval lt(__local391__, 1)
TRACE  | | | Fail lt(__local391__, 1)
TRACE  | | | Redo count(__local559__, __local391__)
TRACE  | | | Redo __local559__ = data.appshield.dockerfile.DS002.get_user
TRACE  | | Fail data.appshield.dockerfile.DS002.fail_user_count
TRACE  | Enter data.appshield.dockerfile.DS002.deny
TRACE  | | Eval data.appshield.dockerfile.DS002.fail_last_user_root
TRACE  | | Index data.appshield.dockerfile.DS002.fail_last_user_root (matched 1 rule)
TRACE  | | Enter data.appshield.dockerfile.DS002.fail_last_user_root
TRACE  | | | Eval __local560__ = data.appshield.dockerfile.DS002.get_user
TRACE  | | | Index data.appshield.dockerfile.DS002.get_user (matched 1 rule)
TRACE  | | | Enter data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Eval user = data.lib.docker.user[_]
TRACE  | | | | Index data.lib.docker.user (matched 1 rule)
TRACE  | | | | Enter data.lib.docker.user
TRACE  | | | | | Eval instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | Eval cast_array(__local560__, __local392__)
TRACE  | | | Eval user = __local392__
TRACE  | | | Eval __local561__ = data.appshield.dockerfile.DS002.get_user
TRACE  | | | Index data.appshield.dockerfile.DS002.get_user (matched 1 rule)
TRACE  | | | Enter data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Eval user = data.lib.docker.user[_]
TRACE  | | | | Index data.lib.docker.user (matched 1 rule)
TRACE  | | | | Enter data.lib.docker.user
TRACE  | | | | | Eval instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo data.appshield.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | Eval count(__local561__, __local393__)
TRACE  | | | Eval len = __local393__
TRACE  | | | Eval minus(len, 1, __local394__)
TRACE  | | | Eval user[__local394__] = "root"
TRACE  | | | Exit data.appshield.dockerfile.DS002.fail_last_user_root
TRACE  | | Eval res = "Last USER command in Dockerfile should not be 'root'"
TRACE  | | Exit data.appshield.dockerfile.DS002.deny
TRACE  | Redo data.appshield.dockerfile.DS002.deny
TRACE  | | Redo res = "Last USER command in Dockerfile should not be 'root'"
TRACE  | | Redo data.appshield.dockerfile.DS002.fail_last_user_root
TRACE  | | Redo data.appshield.dockerfile.DS002.fail_last_user_root
TRACE  | | | Redo user[__local394__] = "root"
TRACE  | | | Redo minus(len, 1, __local394__)
TRACE  | | | Redo len = __local393__
TRACE  | | | Redo count(__local561__, __local393__)
TRACE  | | | Redo __local561__ = data.appshield.dockerfile.DS002.get_user
TRACE  | | | Redo user = __local392__
TRACE  | | | Redo cast_array(__local560__, __local392__)
TRACE  | | | Redo __local560__ = data.appshield.dockerfile.DS002.get_user
TRACE  | Exit data.appshield.dockerfile.DS002.deny = _
TRACE  Redo data.appshield.dockerfile.DS002.deny = _
TRACE  | Redo data.appshield.dockerfile.DS002.deny = _
```