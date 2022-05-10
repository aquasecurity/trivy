load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "const.go",
        "file.go",
    ],
    importpath = "github.com/GoogleCloudPlatform/docker-credential-gcr/config",
    visibility = ["//visibility:public"],
    deps = [
        "//util:go_default_library",
        "//vendor/golang.org/x/oauth2:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["config_file_unit_test.go"],
    embed = [":go_default_library"],
)
