# Debugging policies
When working on more complex queries (or when learning Rego), it's useful to see exactly how the policy is applied.
For this purpose you can use the `--trace` flag.
This will output a large trace from Open Policy Agent like the following:

!!! tip
    Only failed policies show traces. If you want to debug a passed policy, you need to make it fail on purpose.

```shell
$ trivy conf --trace configs/
2022-05-16T13:47:58.853+0100	INFO	Detected config files: 1

Dockerfile (dockerfile)
=======================
Tests: 23 (SUCCESSES: 21, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 0)

MEDIUM: Specify a tag in the 'FROM' statement for image 'alpine'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.

See https://avd.aquasec.com/misconfig/ds001
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:1
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 [ FROM alpine:latest
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


HIGH: Last USER command in Dockerfile should not be 'root'
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Dockerfile:3
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   3 [ USER root
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────



ID: DS001
File: Dockerfile
Namespace: builtin.dockerfile.DS001
Query: data.builtin.dockerfile.DS001.deny
Message: Specify a tag in the 'FROM' statement for image 'alpine'
TRACE  Enter data.builtin.dockerfile.DS001.deny = _
TRACE  | Eval data.builtin.dockerfile.DS001.deny = _
TRACE  | Index data.builtin.dockerfile.DS001.deny (matched 1 rule)
TRACE  | Enter data.builtin.dockerfile.DS001.deny
TRACE  | | Eval output = data.builtin.dockerfile.DS001.fail_latest[_]
TRACE  | | Index data.builtin.dockerfile.DS001.fail_latest (matched 1 rule)
TRACE  | | Enter data.builtin.dockerfile.DS001.fail_latest
TRACE  | | | Eval output = data.builtin.dockerfile.DS001.image_tags[_]
TRACE  | | | Index data.builtin.dockerfile.DS001.image_tags (matched 2 rules)
TRACE  | | | Enter data.builtin.dockerfile.DS001.image_tags
TRACE  | | | | Eval from = data.lib.docker.from[_]
TRACE  | | | | Index data.lib.docker.from (matched 1 rule)
TRACE  | | | | Enter data.lib.docker.from
TRACE  | | | | | Eval instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "from"
TRACE  | | | | | Exit data.lib.docker.from
TRACE  | | | | Redo data.lib.docker.from
TRACE  | | | | | Redo instruction.Cmd = "from"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "from"
TRACE  | | | | | Fail instruction.Cmd = "from"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "from"
TRACE  | | | | | Fail instruction.Cmd = "from"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | Eval name = from.Value[0]
TRACE  | | | | Eval not startswith(name, "$")
TRACE  | | | | Enter startswith(name, "$")
TRACE  | | | | | Eval startswith(name, "$")
TRACE  | | | | | Fail startswith(name, "$")
TRACE  | | | | Eval data.builtin.dockerfile.DS001.parse_tag(name, __local505__)
TRACE  | | | | Index data.builtin.dockerfile.DS001.parse_tag (matched 2 rules)
TRACE  | | | | Enter data.builtin.dockerfile.DS001.parse_tag
TRACE  | | | | | Eval split(name, ":", __local504__)
TRACE  | | | | | Eval [img, tag] = __local504__
TRACE  | | | | | Exit data.builtin.dockerfile.DS001.parse_tag
TRACE  | | | | Eval [img, tag] = __local505__
TRACE  | | | | Eval output = {"cmd": from, "img": img, "tag": tag}
TRACE  | | | | Exit data.builtin.dockerfile.DS001.image_tags
TRACE  | | | Redo data.builtin.dockerfile.DS001.image_tags
TRACE  | | | | Redo output = {"cmd": from, "img": img, "tag": tag}
TRACE  | | | | Redo [img, tag] = __local505__
TRACE  | | | | Redo data.builtin.dockerfile.DS001.parse_tag(name, __local505__)
TRACE  | | | | Redo data.builtin.dockerfile.DS001.parse_tag
TRACE  | | | | | Redo [img, tag] = __local504__
TRACE  | | | | | Redo split(name, ":", __local504__)
TRACE  | | | | Enter data.builtin.dockerfile.DS001.parse_tag
TRACE  | | | | | Eval tag = "latest"
TRACE  | | | | | Eval not contains(img, ":")
TRACE  | | | | | Enter contains(img, ":")
TRACE  | | | | | | Eval contains(img, ":")
TRACE  | | | | | | Exit contains(img, ":")
TRACE  | | | | | Redo contains(img, ":")
TRACE  | | | | | | Redo contains(img, ":")
TRACE  | | | | | Fail not contains(img, ":")
TRACE  | | | | | Redo tag = "latest"
TRACE  | | | | Redo name = from.Value[0]
TRACE  | | | | Redo from = data.lib.docker.from[_]
TRACE  | | | Enter data.builtin.dockerfile.DS001.image_tags
TRACE  | | | | Eval from = data.lib.docker.from[i]
TRACE  | | | | Index data.lib.docker.from (matched 1 rule)
TRACE  | | | | Eval name = from.Value[0]
TRACE  | | | | Eval cmd_obj = input.stages[j][k]
TRACE  | | | | Eval possibilities = {"arg", "env"}
TRACE  | | | | Eval cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Fail cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Redo possibilities = {"arg", "env"}
TRACE  | | | | Redo cmd_obj = input.stages[j][k]
TRACE  | | | | Eval possibilities = {"arg", "env"}
TRACE  | | | | Eval cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Fail cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Redo possibilities = {"arg", "env"}
TRACE  | | | | Redo cmd_obj = input.stages[j][k]
TRACE  | | | | Eval possibilities = {"arg", "env"}
TRACE  | | | | Eval cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Fail cmd_obj.Cmd = possibilities[l]
TRACE  | | | | Redo possibilities = {"arg", "env"}
TRACE  | | | | Redo cmd_obj = input.stages[j][k]
TRACE  | | | | Redo name = from.Value[0]
TRACE  | | | | Redo from = data.lib.docker.from[i]
TRACE  | | | Eval __local752__ = output.img
TRACE  | | | Eval neq(__local752__, "scratch")
TRACE  | | | Eval __local753__ = output.img
TRACE  | | | Eval not data.builtin.dockerfile.DS001.is_alias(__local753__)
TRACE  | | | Enter data.builtin.dockerfile.DS001.is_alias(__local753__)
TRACE  | | | | Eval data.builtin.dockerfile.DS001.is_alias(__local753__)
TRACE  | | | | Index data.builtin.dockerfile.DS001.is_alias (matched 1 rule, early exit)
TRACE  | | | | Enter data.builtin.dockerfile.DS001.is_alias
TRACE  | | | | | Eval img = data.builtin.dockerfile.DS001.get_aliases[_]
TRACE  | | | | | Index data.builtin.dockerfile.DS001.get_aliases (matched 1 rule)
TRACE  | | | | | Enter data.builtin.dockerfile.DS001.get_aliases
TRACE  | | | | | | Eval from_cmd = data.lib.docker.from[_]
TRACE  | | | | | | Index data.lib.docker.from (matched 1 rule)
TRACE  | | | | | | Eval __local749__ = from_cmd.Value
TRACE  | | | | | | Eval data.builtin.dockerfile.DS001.get_alias(__local749__, __local503__)
TRACE  | | | | | | Index data.builtin.dockerfile.DS001.get_alias (matched 1 rule)
TRACE  | | | | | | Enter data.builtin.dockerfile.DS001.get_alias
TRACE  | | | | | | | Eval __local748__ = values[i]
TRACE  | | | | | | | Eval lower(__local748__, __local501__)
TRACE  | | | | | | | Eval "as" = __local501__
TRACE  | | | | | | | Fail "as" = __local501__
TRACE  | | | | | | | Redo lower(__local748__, __local501__)
TRACE  | | | | | | | Redo __local748__ = values[i]
TRACE  | | | | | | Fail data.builtin.dockerfile.DS001.get_alias(__local749__, __local503__)
TRACE  | | | | | | Redo __local749__ = from_cmd.Value
TRACE  | | | | | | Redo from_cmd = data.lib.docker.from[_]
TRACE  | | | | | Fail img = data.builtin.dockerfile.DS001.get_aliases[_]
TRACE  | | | | Fail data.builtin.dockerfile.DS001.is_alias(__local753__)
TRACE  | | | Eval output.tag = "latest"
TRACE  | | | Exit data.builtin.dockerfile.DS001.fail_latest
TRACE  | | Redo data.builtin.dockerfile.DS001.fail_latest
TRACE  | | | Redo output.tag = "latest"
TRACE  | | | Redo __local753__ = output.img
TRACE  | | | Redo neq(__local752__, "scratch")
TRACE  | | | Redo __local752__ = output.img
TRACE  | | | Redo output = data.builtin.dockerfile.DS001.image_tags[_]
TRACE  | | Eval __local754__ = output.img
TRACE  | | Eval sprintf("Specify a tag in the 'FROM' statement for image '%s'", [__local754__], __local509__)
TRACE  | | Eval msg = __local509__
TRACE  | | Eval __local755__ = output.cmd
TRACE  | | Eval data.lib.docker.result(msg, __local755__, __local510__)
TRACE  | | Index data.lib.docker.result (matched 1 rule)
TRACE  | | Enter data.lib.docker.result
TRACE  | | | Eval object.get(cmd, "EndLine", 0, __local470__)
TRACE  | | | Eval object.get(cmd, "Path", "", __local471__)
TRACE  | | | Eval object.get(cmd, "StartLine", 0, __local472__)
TRACE  | | | Eval result = {"endline": __local470__, "filepath": __local471__, "msg": msg, "startline": __local472__}
TRACE  | | | Exit data.lib.docker.result
TRACE  | | Eval res = __local510__
TRACE  | | Exit data.builtin.dockerfile.DS001.deny
TRACE  | Redo data.builtin.dockerfile.DS001.deny
TRACE  | | Redo res = __local510__
TRACE  | | Redo data.lib.docker.result(msg, __local755__, __local510__)
TRACE  | | Redo data.lib.docker.result
TRACE  | | | Redo result = {"endline": __local470__, "filepath": __local471__, "msg": msg, "startline": __local472__}
TRACE  | | | Redo object.get(cmd, "StartLine", 0, __local472__)
TRACE  | | | Redo object.get(cmd, "Path", "", __local471__)
TRACE  | | | Redo object.get(cmd, "EndLine", 0, __local470__)
TRACE  | | Redo __local755__ = output.cmd
TRACE  | | Redo msg = __local509__
TRACE  | | Redo sprintf("Specify a tag in the 'FROM' statement for image '%s'", [__local754__], __local509__)
TRACE  | | Redo __local754__ = output.img
TRACE  | | Redo output = data.builtin.dockerfile.DS001.fail_latest[_]
TRACE  | Exit data.builtin.dockerfile.DS001.deny = _
TRACE  Redo data.builtin.dockerfile.DS001.deny = _
TRACE  | Redo data.builtin.dockerfile.DS001.deny = _
TRACE


ID: DS002
File: Dockerfile
Namespace: builtin.dockerfile.DS002
Query: data.builtin.dockerfile.DS002.deny
Message: Last USER command in Dockerfile should not be 'root'
TRACE  Enter data.builtin.dockerfile.DS002.deny = _
TRACE  | Eval data.builtin.dockerfile.DS002.deny = _
TRACE  | Index data.builtin.dockerfile.DS002.deny (matched 2 rules)
TRACE  | Enter data.builtin.dockerfile.DS002.deny
TRACE  | | Eval data.builtin.dockerfile.DS002.fail_user_count
TRACE  | | Index data.builtin.dockerfile.DS002.fail_user_count (matched 1 rule, early exit)
TRACE  | | Enter data.builtin.dockerfile.DS002.fail_user_count
TRACE  | | | Eval __local771__ = data.builtin.dockerfile.DS002.get_user
TRACE  | | | Index data.builtin.dockerfile.DS002.get_user (matched 1 rule)
TRACE  | | | Enter data.builtin.dockerfile.DS002.get_user
TRACE  | | | | Eval user = data.lib.docker.user[_]
TRACE  | | | | Index data.lib.docker.user (matched 1 rule)
TRACE  | | | | Enter data.lib.docker.user
TRACE  | | | | | Eval instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Exit data.lib.docker.user
TRACE  | | | | Redo data.lib.docker.user
TRACE  | | | | | Redo instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | | Eval instruction.Cmd = "user"
TRACE  | | | | | Fail instruction.Cmd = "user"
TRACE  | | | | | Redo instruction = input.stages[_][_]
TRACE  | | | | Eval username = user.Value[_]
TRACE  | | | | Exit data.builtin.dockerfile.DS002.get_user
TRACE  | | | Redo data.builtin.dockerfile.DS002.get_user
TRACE  | | | | Redo username = user.Value[_]
TRACE  | | | | Redo user = data.lib.docker.user[_]
TRACE  | | | Eval count(__local771__, __local536__)
TRACE  | | | Eval lt(__local536__, 1)
TRACE  | | | Fail lt(__local536__, 1)
TRACE  | | | Redo count(__local771__, __local536__)
TRACE  | | | Redo __local771__ = data.builtin.dockerfile.DS002.get_user
TRACE  | | Fail data.builtin.dockerfile.DS002.fail_user_count
TRACE  | Enter data.builtin.dockerfile.DS002.deny
TRACE  | | Eval cmd = data.builtin.dockerfile.DS002.fail_last_user_root[_]
TRACE  | | Index data.builtin.dockerfile.DS002.fail_last_user_root (matched 1 rule)
TRACE  | | Enter data.builtin.dockerfile.DS002.fail_last_user_root
TRACE  | | | Eval stage_users = data.lib.docker.stage_user[_]
TRACE  | | | Index data.lib.docker.stage_user (matched 1 rule)
TRACE  | | | Enter data.lib.docker.stage_user
TRACE  | | | | Eval stage = input.stages[stage_name]
TRACE  | | | | Eval users = [cmd | cmd = stage[_]; cmd.Cmd = "user"]
TRACE  | | | | Enter cmd = stage[_]; cmd.Cmd = "user"
TRACE  | | | | | Eval cmd = stage[_]
TRACE  | | | | | Eval cmd.Cmd = "user"
TRACE  | | | | | Fail cmd.Cmd = "user"
TRACE  | | | | | Redo cmd = stage[_]
TRACE  | | | | | Eval cmd.Cmd = "user"
TRACE  | | | | | Exit cmd = stage[_]; cmd.Cmd = "user"
TRACE  | | | | Redo cmd = stage[_]; cmd.Cmd = "user"
TRACE  | | | | | Redo cmd.Cmd = "user"
TRACE  | | | | | Redo cmd = stage[_]
TRACE  | | | | | Eval cmd.Cmd = "user"
TRACE  | | | | | Fail cmd.Cmd = "user"
TRACE  | | | | | Redo cmd = stage[_]
TRACE  | | | | Exit data.lib.docker.stage_user
TRACE  | | | Redo data.lib.docker.stage_user
TRACE  | | | | Redo users = [cmd | cmd = stage[_]; cmd.Cmd = "user"]
TRACE  | | | | Redo stage = input.stages[stage_name]
TRACE  | | | Eval count(stage_users, __local537__)
TRACE  | | | Eval len = __local537__
TRACE  | | | Eval minus(len, 1, __local538__)
TRACE  | | | Eval last = stage_users[__local538__]
TRACE  | | | Eval user = last.Value[0]
TRACE  | | | Eval user = "root"
TRACE  | | | Exit data.builtin.dockerfile.DS002.fail_last_user_root
TRACE  | | Redo data.builtin.dockerfile.DS002.fail_last_user_root
TRACE  | | | Redo user = "root"
TRACE  | | | Redo user = last.Value[0]
TRACE  | | | Redo last = stage_users[__local538__]
TRACE  | | | Redo minus(len, 1, __local538__)
TRACE  | | | Redo len = __local537__
TRACE  | | | Redo count(stage_users, __local537__)
TRACE  | | | Redo stage_users = data.lib.docker.stage_user[_]
TRACE  | | Eval msg = "Last USER command in Dockerfile should not be 'root'"
TRACE  | | Eval data.lib.docker.result(msg, cmd, __local540__)
TRACE  | | Index data.lib.docker.result (matched 1 rule)
TRACE  | | Enter data.lib.docker.result
TRACE  | | | Eval object.get(cmd, "EndLine", 0, __local470__)
TRACE  | | | Eval object.get(cmd, "Path", "", __local471__)
TRACE  | | | Eval object.get(cmd, "StartLine", 0, __local472__)
TRACE  | | | Eval result = {"endline": __local470__, "filepath": __local471__, "msg": msg, "startline": __local472__}
TRACE  | | | Exit data.lib.docker.result
TRACE  | | Eval res = __local540__
TRACE  | | Exit data.builtin.dockerfile.DS002.deny
TRACE  | Redo data.builtin.dockerfile.DS002.deny
TRACE  | | Redo res = __local540__
TRACE  | | Redo data.lib.docker.result(msg, cmd, __local540__)
TRACE  | | Redo data.lib.docker.result
TRACE  | | | Redo result = {"endline": __local470__, "filepath": __local471__, "msg": msg, "startline": __local472__}
TRACE  | | | Redo object.get(cmd, "StartLine", 0, __local472__)
TRACE  | | | Redo object.get(cmd, "Path", "", __local471__)
TRACE  | | | Redo object.get(cmd, "EndLine", 0, __local470__)
TRACE  | | Redo msg = "Last USER command in Dockerfile should not be 'root'"
TRACE  | | Redo cmd = data.builtin.dockerfile.DS002.fail_last_user_root[_]
TRACE  | Exit data.builtin.dockerfile.DS002.deny = _
TRACE  Redo data.builtin.dockerfile.DS002.deny = _
TRACE  | Redo data.builtin.dockerfile.DS002.deny = _
TRACE
```