load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["util.go"],
    importpath = "github.com/GoogleCloudPlatform/docker-credential-gcr/util",
    visibility = ["//visibility:public"],
    deps = ["//util/cmd:go_default_library"],
)

go_test(
    name = "go_default_test",
    srcs = ["util_unit_test.go"],
    embed = [":go_default_library"],
    deps = [
        "//mock/mock_cmd:go_default_library",
        "//util/cmd:go_default_library",
        "//vendor/github.com/golang/mock/gomock:go_default_library",
    ],
)
