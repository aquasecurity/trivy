package builtin.dockerfile.DS001

import data.lib.docker

__rego_metadata__ := {
	"id": "DS001",
	"avd_id": "AVD-DS-0001",
	"title": "':latest' tag used",
	"short_code": "use-specific-tags",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
	"recommended_actions": "Add a tag to the image in the 'FROM' statement",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# returns element after AS
get_alias(values) = alias {
	"as" == lower(values[i])
	alias = values[i + 1]
}

get_aliases[aliases] {
	from_cmd := docker.from[_]
	aliases := get_alias(from_cmd.Value)
}

is_alias(img) {
	img == get_aliases[_]
}

# image_names returns the image in FROM statement.
image_names[image_name] {
	from := docker.from[_]
	image_name := from.Value[0]
}

# image_tags returns the image and tag.
parse_tag(name) = [img, tag] {
	[img, tag] = split(name, ":")
}

# image_tags returns the image and "latest" if a tag is not specified.
parse_tag(img) = [img, tag] {
	tag := "latest"
	not contains(img, ":")
}

#base scenario
image_tags[output] {
	from := docker.from[_]
	name := from.Value[0]
	not startswith(name, "$")
	[img, tag] = parse_tag(name)
	output := {
		"img": img,
		"tag": tag,
		"cmd": from,
	}
}

# If variable is used with FROM then it's value should contain a tag
image_tags[output] {
	some i, j, k, l
	from := docker.from[i]
	name := from.Value[0]

	cmd_obj := input.stages[j][k]

	possibilities := {"arg", "env"}
	cmd_obj.Cmd == possibilities[l]

	startswith(name, "$")

	bare_var := trim_prefix(name, "$")

	startswith(cmd_obj.Value[0], bare_var)

	[_, bare_image_name] := regex.split(`\s*=\s*`, cmd_obj.Value[0])

	[img, tag] = parse_tag(bare_image_name)
	output := {
		"img": img,
		"tag": tag,
		"cmd": from,
	}
}

# fail_latest is true if image is not scratch
# and image is not an alias
# and tag is latest.
fail_latest[output] {
	output := image_tags[_]
	output.img != "scratch"
	not is_alias(output.img)
	output.tag == "latest"
}

deny[res] {
	output := fail_latest[_]
	msg := sprintf("Specify a tag in the 'FROM' statement for image '%s'", [output.img])
	res := docker.result(msg, output.cmd)
}
